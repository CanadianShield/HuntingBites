**❓ Hypothesis:** a threat actor is known to use specific [LOL binaries](https://www.bing.com/search?q=What+are+LOLBins) after a successful RDP password spray. 

**📃 To-do:**
 - we assume the attacker is in
 - focus on the first 1 minute of a connection

We don't focus on the password spray this time.

**⏭️ Next:** use more elegant ways...

The LOLBins of interrest for this threat actor are the following:
 - `whoami.exe` used to know group membership and local privileges of the compromised account 
 - `ipconfig.exe` used to explore the network settings and DNS cache of the system
 - `winrs.exe` command line tool to execute code remotely using WinRM

Process creations in Windows are tracked in the event ID `4688`. Let's explore it a little:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| take 10
```

Exploring that data we can see that many processes are created in the context of the machine. While it could be interresting for some threat detection scenarios, in our case process created by this actor will be assumed to be in the context of a user. So we can filter out many process creation with the following:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
```

Let's see if we have the LOL processs in our dataset:

```kql
let LOLList = dynamic(["ipconfig.exe","whoami.exe","winrs.exe"]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
| where Process in (LOLList)
```

Of course this only gives us if the processes were created. Not that there were used within 1 minute. For that we will need to bundle them in bucket of 1 minute.

```kql
let LOLList = dynamic(["ipconfig.exe","whoami.exe","winrs.exe"]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
| where Process in~ (LOLList)
| summarize ProcessSet = make_set(tolower(Process)) by bin(TimeGenerated, 1m), Computer, SubjectAccount
```

🔗 [make_set documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/make-set-aggregation-function)

Now we can ask for buckets of ProcesSet that matches our variable `LOLList`. At this point there are different ways to check if we have a match between `ProcessSet` and `LOLList`. The easiest way would be to check the number of items. As make_set only keep unique values, if the number of values in it is the same as the number of value in `LOLList` then we know it's a match. A fancier way to do it is to check if all `LOLList` items exist in the set. It's more practical in case the the second array could contain something more. Let say that `PorcessSet` has all the process, not only the one that are in `LOLList`. Then this fancier method woudl just work regardless.

🔗 [set_difference documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/set-difference-function)

Note that the order matter, we need `LOLList` as a first argument.

```kql
let LOLList = dynamic(["ipconfig.exe","whoami.exe","winrs.exe"]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
| where Process in (LOLList)
| summarize ProcessSet = make_set(tolower(Process)) by bin(TimeGenerated, 1m), Computer, SubjectAccount
| where array_length(set_difference(LOLList, ProcessSet)) == 0
```

The problem with that approach is that it doesn't really tell us what we have all the processes running within 1 minute it tells us that we have them in arbitrary buckets of 1 minute. And the bucket has different start and end times depending on when it is ran as the time limit in this query is based on `ago()` which is contextual of the exeution time of the query.

```kql
print ago(1d)
// make a note of the output
// wait 5 second and run it again
```

So, we could have let say process 1 and 2 in at the end of one bucket and process 3 at the beggining of a second bucket. They are still within one minute appart but in two buckets. One way to deal with that is to look at the bucket and the one before the current one:

```kql
let LOLList = dynamic(["ipconfig.exe","whoami.exe","winrs.exe"]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
| where Process in (LOLList)
| summarize ProcessSet = make_set(tolower(Process)) by bin(TimeGenerated, 1m), Computer, SubjectAccount
| order by TimeGenerated asc
| serialize 
| extend NewProcessSet = array_concat(ProcessSet, prev(ProcessSet))
| where array_length(set_difference(LOLList, NewProcessSet)) == 0
| project TimeGenerated, Computer, SubjectAccount, NewProcessSet
```

🔗 [serialize documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/serialize-operator)

Great! But it doesn't actually do exactly what we need. As in fact, we are now looking at buckets of 2 minutes. Which is probably fine, but what if we reallu want all the stuf to be 1 minute appart. We will need to bring the first process match and the last process match in our aggregation.

```kql
let LOLList = dynamic(["ipconfig.exe","whoami.exe","winrs.exe"]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
| where Process in (LOLList)
| summarize ProcessSet = make_set(tolower(Process)), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by bin(TimeGenerated, 1m), Computer, SubjectAccount
| order by TimeGenerated asc
| serialize 
| extend NewProcessSet = array_concat(ProcessSet, prev(ProcessSet))
| where array_length(set_difference(LOLList, NewProcessSet)) == 0
| where LastSeen - FirstSeen <= 1m
| project TimeGenerated, Computer, SubjectAccount, NewProcessSet
```

We are getting somewhere. But wouldn't be a more elegant way of doing that? Plenty! Like using [scan](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/scan-operator) or (row_window_session)[https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/row-window-session-function] (which is kinda what we have done, but in a native and much shorter way). But we'll explore that in a another episode...

Now, we need something else here. We didn't really need those processes to be 1 minute apart of each other. They needed to be 1 minute apart from a succesful RDP connection. Good effort but eh, we need to narrow down that to the one who took place in a RDP session.

RDP sessions can identified looking at the `LogonType` of the event ID `4624`. And this is a quick way to build a mapping in case you don't remember what are the possible values:

```kql
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID == 4624
| distinct LogonType, LogonTypeName
```

Let's explore the data:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where LogonType == 10
```

There seem to be a lot of duplicate. To keep unique logons we are going to filter out empty (LogonGuid)[https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624].
We need `LogonType == 10`. Let's identify the session and then map them to our process sets as long as the last process execution time is within 1 minute of the session start time.

```kql
let LOLList = dynamic(["ipconfig.exe","whoami.exe","winrs.exe"]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
| where Process in (LOLList)
| summarize ProcessSet = make_set(tolower(Process)), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by bin(TimeGenerated, 1m), Computer, SubjectAccount
| order by TimeGenerated asc
| serialize 
| extend NewProcessSet = array_concat(ProcessSet, prev(ProcessSet))
| where array_length(set_difference(LOLList, NewProcessSet)) == 0
| where LastSeen - FirstSeen <= 1m
| project TimeGenerated, Computer, SubjectAccount, NewProcessSet, FirstSeen, LastSeen
| join kind=leftouter (
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where LogonType == 10
    | where LogonGuid != "00000000-0000-0000-0000-000000000000"
    | project SessionStartTime = TimeGenerated, Computer, TargetAccount
) on Computer, $left.SubjectAccount == $right.TargetAccount
| where LastSeen - SessionStartTime <= 1m
| project Computer, SessionStartTime, NewProcessSet, SubjectAccount, FirstSeen, LastSeen
```

Our right table is smaller than our left we should really switch it... I let you do that :)






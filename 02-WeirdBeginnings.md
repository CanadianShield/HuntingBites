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

Of course this only gives us if the prcesses where used. Not that there were used within 1 minute. For that we will need to bundle them in bucket of 1 minute.

```kql
let LOLList = dynamic(["ipconfig.exe","whoami.exe","winrs.exe"]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
| where Process in~ (LOLList)
| summarize ProcessSet = make_set(tolower(Process)) by bin(TimeGenerated, 1m), Computer, SubjectAccount
```

Now we can ask for buckets of ProcesSet that matches our variable `LOLList`.

The problem with that approach is that it doesn't really tell us what we have

❓ Hypothesis: attackers can be using new PE to compromise endpoints

📃 To-do:

- Find rare processes   
- Find rare process associations   
- Find rare process trees    
  
⏭️ Next: use the process trees to find anomalies outside of the XDR

First, let's check what the DeviceProcessEvent table looks like:

```kql
DeviceProcessEvents
| take 1
```

Let's do some stastistc based on process names, which in the table is actually called `FileName`.

```kql
DeviceProcessEvents
| summarize Total = count() by FileName
| order by Total asc
```

Now that we have a count, let's explore the process that showed only one time in our environment and run it against the `FileProfile()` function to get prevalance information.

🔗 [FileProfile() documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function)

```kql
DeviceProcessEvents
| summarize Total = count() by FileName, SHA256
| where Total == 1
| invoke FileProfile("SHA256")
| where GlobalPrevalence < 500
```

We can do the same thing for the parent processes:

```kql
DeviceProcessEvents
| summarize Total = count() by InitiatingProcessFileName, SHA256
| where Total == 1
| invoke FileProfile("SHA256")
```

After reading some threat intel report, it seems that it would be interresting to check what processes are started by processes such as `powershell.exe` and `outlook.exe` (yes that's totally arbitrary). Also, in the dataset we are exloring, there is an oddity... The process `calc.exe` seems to start processes...

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("powershell.exe","outlook.exe","calc.exe")
| summarize count() by FileName, InitiatingProcessFileName
```

So we get this machine called `broken4` which has some cool stuff (`calc.exe` is starting things...). Let's focus our search on it using the [graph capabilities of KQL](https://learn.microsoft.com/en-us/kusto/query/graph-overview). We are going to use `make-graph` to turn our tabular data to a graph and then use `graph-match` to explore that data. 

🔗 [make-graph documentation](https://learn.microsoft.com/en-us/kusto/query/make-graph-operator)    
🔗 [graph-match documentation](https://learn.microsoft.com/en-us/kusto/query/graph-match-operator)

To turn our data to a graph, we will need a table with a list of nodes (processes) and a table with the list of edges (relation between the nodes, between the processes). Interrestingly, the "DeviceProcessEvents" has both. Within the same table we have the process and its relationship with another process: `InitiatingProcessFileName` is starting `FileName`, or using their identifiers, `InitiatingProcessId` is starting `ProcessId`. Let's build a graph for our device of interest:

```kql
let Processes = DeviceProcessEvents
| where DeviceName == "broken4";
Processes
| make-graph InitiatingProcessId --> ProcessId with Processes on ProcessId
```

This doesn't work as-is as the result is a graph and not a [tabular output](https://learn.microsoft.com/en-us/kusto/query/tabular-expression-statements). So we'll explore it asking the paths between a parent process and its child processes all identified by their PID. 

```kql
let Processes = DeviceProcessEvents
| where DeviceName == "broken4";
Processes
| make-graph InitiatingProcessId --> ProcessId with Processes on ProcessId
| graph-match (ParentProcess) -[Initiated*2..10]-> ()
  where isnotempty(ParentProcess.InitiatingProcessFileName)
  project ParentProcess = ParentProcess.InitiatingProcessFileName, ProcessTree = Initiated.FileName
```

This explores the paths between a parent process called `ParentProcess` to any process `()`. Path needs to be composed between 2 and 10 hops. It means that if a `ParentProcess` created a process which in its turn, didn't not create another process, this path will not be kept. And if a `ParentProcess` ended created a process tree depeer than 10 hops, we also stop looking at it (for perf reasons, we need to fix limits there...).

Looks good! Yet, there are a few problems with this... First of all, the PID are not unique. Windows can reuse them, so we might have found imaginary paths... We need to create a unique identifier for the processes. Normally we would use a `hash_many()` function but here we are going to do a simple concatenation with `strcat()` just for learning and readability.  

```kql
let Processes = DeviceProcessEvents
| where DeviceName == "broken4"
| extend ProcessCompoundId = strcat(DeviceId,"-", FileName,"-", ProcessId,"-", ProcessCreationTime),
    InitiatingProccesCompoundId = strcat(DeviceId, "-", InitiatingProcessFileName,"-", InitiatingProcessId,"-", InitiatingProcessCreationTime);
Processes
| make-graph InitiatingProccesCompoundId --> ProcessCompoundId with Processes on ProcessCompoundId
| graph-match (ParentProcess) -[Initiated*2..10]-> ()
  where isnotempty(ParentProcess.InitiatingProcessFileName)
  project ParentProcessId = ParentProcess.InitiatingProccesCompoundId, ParentProcess = ParentProcess.InitiatingProcessFileName, ProcessTree = Initiated.FileName
```

Getting better, we have validated path. But really, explore the `hash_many()` function the next time to get more succinct.

🔗 [hash_many() documentation](https://learn.microsoft.com/en-us/kusto/query/hash-many-function)

Now let's explore rare process trees. Let's keep the longest path per parent process:

```kql
let Processes = DeviceProcessEvents
| where DeviceName == "broken4"
| extend ProcessCompoundId = strcat(DeviceId,"-", FileName,"-", ProcessId,"-", ProcessCreationTime),
    InitiatingProccesCompoundId = strcat(DeviceId, "-", InitiatingProcessFileName,"-", InitiatingProcessId,"-", InitiatingProcessCreationTime);
Processes
| make-graph InitiatingProccesCompoundId --> ProcessCompoundId with Processes on ProcessCompoundId
| graph-match (ParentProcess) -[Initiated*2..10]-> ()
  where isnotempty(ParentProcess.InitiatingProcessFileName)
  project ParentProcessId = ParentProcess.InitiatingProccesCompoundId, ParentProcess = ParentProcess.InitiatingProcessFileName, ProcessTree = Initiated.FileName
| summarize Depth = arg_max(array_length(ProcessTree),*) by ParentProcessId
```

... TO BE CONTINUED

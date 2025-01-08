❓ Hypothesis: NOT A CLASSIC HUNTING SESSION TODAY - Pentester boasts that by compromising a banal test account (called "TEST TEST") they got to reset the CEO’s accounts and access her mailbox 

📃 To-do:

- Examine what is that TEST account about   
- Is there a path from that account to the CEO   
- Is there a path from an exposed Internet server to that TEST account   

⏭️ Next: find the shortest path from an exposed server to the CEO’s account without using privileged accounts


Let's start to see how to retrieve information about this test user:

```kql
IdentityInfo
| where AccountDisplayName contains "TEST TEST"
```

This returns more than one line. We are just interested in the latest entry in the table, that reflect the current status of this user using [arg_max()](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function).

```kql
IdentityInfo
| where Timestamp > ago(14d)
| where AccountDisplayName contains "TEST TEST"
| summarize arg_max(Timestamp, *)
```

That is the latest version. Let see if there are any actions of interest in the `BehaviorAnalytics` table (this table is populate from the UBEA feature in Sentinel [Advanced threat detection with User and Entity Behavior Analytics (UEBA) in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics).

```kql
BehaviorAnalytics
| where UserName contains "TESTTEST"
| summarize max(InvestigationPriority)
```

Now we are going to use the [Exposure Management](https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management) feature of the XDR. Let's explore the node table and see what we have for this account:

```kql
ExposureGraphNodes
| where NodeName == "TEST TEST"
```

Let's see what are the direct relationships for this user. Meaning, from this user, where can we **directly** go to:

```kql
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[DirectPath]->(Target)
    where Source.NodeName == "TEST TEST"
    project Source.NodeName, DirectPath.EdgeLabel, Target.NodeName
```

Now what can we do from this test, indirectly using up to 5 hops:

```kql
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.NodeName == "TEST TEST" and Target.NodeName == "CEO"
    project Source.NodeName, Path.EdgeLabel, Target.NodeName
```

ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.NodeName == "TEST TEST" and Target.NodeName == "CEO"
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName

ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-shortest-paths (Source)-[Path*1..5]->(Target)
    where Source.NodeName == "TEST TEST" and Target.NodeName == "CEO"
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName

ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.Categories has "device" and Target.NodeName == "TEST TEST"
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName

ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing 
    and Target.NodeName == "TEST TEST"
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName


ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount != 1
| distinct NodeId, NodeName

ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId, NodeName


let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "TEST TEST"
    and Path.TargetNodeId !in (Gods)
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName


let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "TEST TEST"
    and Path.TargetNodeId !in (Gods)
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName
| mv-apply Path_EdgeLabel, Path_TargetNodeName on (
    extend P = strcat(Source_NodeName,"-[", Path_EdgeLabel, "]-(" , Path_TargetNodeName , ")")
    | summarize L = make_list(P)
    | extend AsciiPath = strcat_array(L,"")
)
| project AsciiPath



let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "TEST TEST"
    and Path.TargetNodeId !in (Gods)
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName
| mv-apply Path_EdgeLabel, Path_TargetNodeName on (
    extend P = strcat(Source_NodeName,"-[", Path_EdgeLabel, "]-(" , Path_TargetNodeName , ")")
    | summarize L = make_list(P)
    | extend AsciiPath = strcat_array(L,"")
)
| project AsciiPath


let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "TEST TEST"
    and Path.TargetNodeId !in (Gods)
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName
| mv-apply Path_EdgeLabel, Path_TargetNodeName on (
    extend P = strcat("-[", Path_EdgeLabel, "]-(" , Path_TargetNodeName , ")")
    | summarize L = make_list(P)
    | extend AsciiPath = strcat_array(L,"")
)
| project strcat("(",Source_NodeName,")",AsciiPath)


let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "CEO"
    and Path.TargetNodeId !in (Gods)
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName
| mv-apply Path_EdgeLabel, Path_TargetNodeName on (
    extend P = strcat("-[", Path_EdgeLabel, "]-(" , Path_TargetNodeName , ")")
    | summarize L = make_list(P)
    | extend AsciiPath = strcat_array(L,"")
)
| project strcat("(",Source_NodeName,")",AsciiPath


let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..8]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "CEO"
    and Path.TargetNodeId !in (Gods)
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName
| mv-apply Path_EdgeLabel, Path_TargetNodeName on (
    extend P = strcat("-[", Path_EdgeLabel, "]-(" , Path_TargetNodeName , ")")
    | summarize L = make_list(P)
    | extend AsciiPath = strcat_array(L,"")
)
| project strcat("(",Source_NodeName,")",AsciiPath


let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path1*1..5]->(Partner)-[Path2*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "CEO"
    and Partner.NodeName contains "partner"
    and Path1.TargetNodeId !in (Gods)
    and Path2.TargetNodeId !in (Gods)
    project Source.NodeName, Path.EdgeLabel, Path.TargetNodeName, Target.NodeName


let Gods = ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties.rawData.adminCount == 1
| distinct NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path1*1..5]->(Partner)-[Path2*1..5]->(Target)
    where Source.Categories has "device"
    and Source.NodeProperties.rawData.isInternetFacing
    and Target.NodeName == "CEO"
    and Partner.NodeName contains "partner"
    and Path1.TargetNodeId !in (Gods)
    and Path2.TargetNodeId !in (Gods)
    project Source.NodeName, Path1.EdgeLabel, Path1.TargetNodeName,Path2.EdgeLabel, Path2.TargetNodeName, Target.NodeName
    

IdentityInfo
| where AccountDisplayName contains "TEST TEST"

IdentityInfo
| where Timestamp > ago(14d)
| where AccountDisplayName contains "TEST TEST"
| summarize arg_max(Timestamp, *)


BehaviorAnalytics
| where UserName contains "TESTTEST"
| summarize max(InvestigationPriority)

ExposureGraphNodes
| where NodeName == "TEST TEST"

xposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[DirectPath]->(Target)
    where Source.NodeName == "TEST TEST"
    project Source.NodeName, DirectPath.EdgeLabel, Target.NodeName

ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Source)-[Path*1..5]->(Target)
    where Source.NodeName == "TEST TEST" and Target.NodeName == "CEO"
    project Source.NodeName, Path.EdgeLabel, Target.NodeName

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
    

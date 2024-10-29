❓ Hypothesis: attackers are adding their own MFA methods to compromised users

📃 To-do:

- Find potential compromised users sign-ins   
- Find MFA registration following those sign-ins   

⏭️ Next: use the same logic to add addition post compromise steps (such as adding a mailbox redirection rule)

First let's see what's the audit record when user update their MFA methods. Too lazy to check the documentation, so let's check directly in the AuditLogs table:

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where *  contains "security info"
```

Ok now we see clearer let's fine tune the filter.

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where Category == "UserManagement"
| where OperationName == "User registered security info" 
| project TimeGenerated, OperationName, ResultDescription, UserPrincipalName = tostring(TargetResources[0].userPrincipalName), IPAddress = tostring(InitiatedBy.user.ipAddress), Result
```

What about suspicious signins? Let's focus on the [Unfamilliar signin properties](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#unfamiliar-sign-in-properties) detection in Identity Protection. 

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where * contains "unfamiliarFeatures"
```

Now with a proper filter:

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where RiskEventTypes has_any ("unfamiliarFeatures") and RiskDetail == "userPassedMFADrivenByRiskBasedPolicy"
| project TimeGenerated, OperationName, UserPrincipalName, AppDisplayName, IPAddress, ResultType
```

Let's union the two and use partition to just display 2 record max per query to ensure everything works fine. 

🔗 (partition documentation)[https://learn.microsoft.com/en-us/kusto/query/partition-operator]

```kql
union (AuditLogs
| where TimeGenerated > ago(14d)
| where Category == "UserManagement"
| where OperationName in~ ("User registered security info","User started security info registration","User registered all required security info")
| project TimeGenerated, OperationName, ResultDescription, Result, UserPrincipalName = tostring(TargetResources[0].userPrincipalName), IPAddress = tostring(InitiatedBy.user.ipAddress)
),(
SigninLogs
| where TimeGenerated > ago(14d)
| where RiskEventTypes has_any ("unfamiliarFeatures") and RiskDetail == "userPassedMFADrivenByRiskBasedPolicy"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType)
| partition hint.strategy=native by UserPrincipalName (
  limit 2
)
```

Note that we use `hint.strategy=native` as it is very likely that we go above the default legacy strategy limit.   
Let's put that together ordered by TimeGenerated and use scan to perfom a subquery for each record and try to identify a sequence. 

🔗 (scan documentation)[https://learn.microsoft.com/en-us/kusto/query/scan-operator]

```kql
union (AuditLogs
| where TimeGenerated > ago(14d)
| where Category == "UserManagement"
| where OperationName in~ ("User registered security info","User started security info registration","User registered all required security info")
| project TimeGenerated, OperationName, ResultDescription, Result, UserPrincipalName = tostring(TargetResources[0].userPrincipalName), IPAddress = tostring(InitiatedBy.user.ipAddress)
),(
SigninLogs
| where TimeGenerated > ago(14d)
| where RiskEventTypes has_any ("unfamiliarFeatures") and RiskDetail == "userPassedMFADrivenByRiskBasedPolicy"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType)
| partition hint.strategy=native by UserPrincipalName (
    order by TimeGenerated asc
    |  scan with 
    (
        step s1 output=none: ResultType == "0" ;
        step s2 output=last: OperationName == "User registered security info" and ((TimeGenerated - s1.TimeGenerated) / 1m) < 15 ;
    )
)
```

Great! Well, we could have done that with a simple left outer join... But scan has its value when we want to identify more steps... Let's add to the mix another step. Let's say a user adding a mailbox redirection rule within the first 15 minutes of the suspicious signin. First we'll need a query to list all redirection rules:

```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where RecordType == "ExchangeAdmin"
| mv-apply todynamic(Parameters) on (
    where Parameters.Name == "ForwardingSmtpAddress"
    | extend ForwardingSmtpAddress = Parameters.Value
)
| project TimeGenerated, UserPrincipalName = tolower(UserId), OperationName = Operation, IPAddress = tostring(split(ClientIP, ":")[0]), ForwardingSmtpAddress
```

🔗 (mv-apply documentation)[https://learn.microsoft.com/en-us/kusto/query/mv-apply-operator]

Let put that together:

```kql
union (AuditLogs
| where TimeGenerated > ago(14d)
| where Category == "UserManagement"
| where OperationName in~ ("User registered security info","User started security info registration","User registered all required security info")
| project TimeGenerated, OperationName, ResultDescription, Result, UserPrincipalName = tostring(TargetResources[0].userPrincipalName), IPAddress = tostring(InitiatedBy.user.ipAddress)
),(
SigninLogs
| where TimeGenerated > ago(14d)
| where RiskEventTypes has_any ("unfamiliarFeatures") and RiskDetail == "userPassedMFADrivenByRiskBasedPolicy"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType),(
OfficeActivity
| where TimeGenerated > ago(14d)
| where RecordType == "ExchangeAdmin"
| mv-apply todynamic(Parameters) on (
    where Parameters.Name == "ForwardingSmtpAddress"
    | extend ForwardingSmtpAddress = Parameters.Value
)
| project TimeGenerated, UserPrincipalName = tolower(UserId), OperationName = Operation, IPAddress = tostring(split(ClientIP, ":")[0]), ForwardingSmtpAddress
)
| partition hint.strategy=native by UserPrincipalName (
    order by TimeGenerated asc
    |  scan with 
    (
        step s1 output=none: ResultType == "0" ;
        step s2 output=none: OperationName == "User registered security info" and ((TimeGenerated - s1.TimeGenerated) / 1m) < 15 ;
        step s3 : OperationName == "Set-Mailbox" and ((TimeGenerated - s2.TimeGenerated) / 1m) < 15 and IPAddress == s1.IPAddress ;
    )
)
```
Here we have it. It will return the Set-Mailbox operation perform after a suspicious signin and an MFA registration. Let's add some new columns for clarity using the `declare` parameter in `scan`:

```kql
union (AuditLogs
| where TimeGenerated > ago(14d)
| where Category == "UserManagement"
| where OperationName in~ ("User registered security info","User started security info registration","User registered all required security info")
| project TimeGenerated, OperationName, ResultDescription, Result, UserPrincipalName = tostring(TargetResources[0].userPrincipalName), IPAddress = tostring(InitiatedBy.user.ipAddress)
),(
SigninLogs
| where TimeGenerated > ago(14d)
| where RiskEventTypes has_any ("unfamiliarFeatures") and RiskDetail == "userPassedMFADrivenByRiskBasedPolicy"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType),(
OfficeActivity
| where TimeGenerated > ago(14d)
| where RecordType == "ExchangeAdmin"
| mv-apply todynamic(Parameters) on (
    where Parameters.Name == "ForwardingSmtpAddress"
    | extend ForwardingSmtpAddress = Parameters.Value
)
| project TimeGenerated, UserPrincipalName = tolower(UserId), OperationName = Operation, IPAddress = tostring(split(ClientIP, ":")[0]), ForwardingSmtpAddress
)
| partition hint.strategy=native by UserPrincipalName (
    order by TimeGenerated asc
    |  scan declare (SuspiciousLogonTime:datetime, SuspiciousMFARegistration:datetime) with 
    (
        step s1 output=none: ResultType == "0" ;
        step s2 output=none: OperationName == "User registered security info" and ((TimeGenerated - s1.TimeGenerated) / 1m) < 15 ;
        step s3 : OperationName == "Set-Mailbox" and ((TimeGenerated - s2.TimeGenerated) / 1m) < 15 and IPAddress == s1.IPAddress => SuspiciousLogonTime = s1.TimeGenerated, SuspiciousMFARegistration = s2.TimeGenerated;
    )
)
| project-reorder SuspiciousLogonTime, SuspiciousMFARegistration
```

Tada! 🎉 

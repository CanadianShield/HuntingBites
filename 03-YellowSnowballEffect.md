❓ Hypothesis: attackers are adding their own MFA methods to compromised users

📃 To-do:

- Find potential compromised users sign-ins   
- Find MFA registration following those sign-ins   

⏭️ Next: use the same logic to add addition post compromise steps (such as adding a mailbox redirection rule)

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where *  contains "security info"
```

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where Category == "UserManagement"
| where OperationName == "User registered security info" 
| project TimeGenerated, OperationName, ResultDescription, UserPrincipalName = tostring(TargetResources[0].userPrincipalName), IPAddress = tostring(InitiatedBy.user.ipAddress), Result
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where * contains "unfamiliarFeatures"
```

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where RiskEventTypes has_any ("unfamiliarFeatures") and RiskDetail == "userPassedMFADrivenByRiskBasedPolicy"
| project TimeGenerated, OperationName, UserPrincipalName, AppDisplayName, IPAddress, ResultType
```

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

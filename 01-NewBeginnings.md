**❓ Hypothesis** compromised users might connect from IP addresses we’ve never seen before.
**📃 To-do**: 
  - Dig into the data to see if we have IP addresses that we never seen before
  - Try to determine if that’s just a new IP used by the user looking at geography   

**⏭️ Next:** use the same logic with other data point 


Let's see what are the known IPs in our tenant
```kql
SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| distinct IPAddress
```

Let's store that in a variable and check if we have attempts today from new IPs

```kql
let KnownIPs = SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| distinct IPAddress;
SigninLogs
| where TimeGenerated > ago(1d)
| where IPAddress !in (KnownIPs)
| distinct IPAddress, UserPrincipalName
```

🔗 [!in documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/not-in-cs-operator)


Well that tells us about new IP, but that's not user specific. Let's see if we can see new IP per user

```kql
let KnownIPperUsers = SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| distinct IPAddress,UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
//| where IPAddress !in (KnownIPs)
| join kind=leftanti (KnownIPperUsers) on IPAddress, UserPrincipalName
| distinct IPAddress, UserPrincipalName
```

🔗 [join documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/join-operator?pivots=azuredataexplorer)

Technically, if are purist when we do a join in KQL, the left table should be the smaller table

```kql
SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| distinct IPAddress,UserPrincipalName
| join kind=rightanti (
    SigninLogs
    | where TimeGenerated > ago(1d)
) on IPAddress, UserPrincipalName
| distinct IPAddress, UserPrincipalName
```

Well new IP doesn't mean new geo location, so let's do user connecting from new location instead

```kql
SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| distinct Location,UserPrincipalName
| join kind=rightanti (
    SigninLogs
    | where TimeGenerated > ago(1d)
) on Location, UserPrincipalName
| distinct Location, UserPrincipalName
```

Wait, canadian accounts connecting from Canada for the first time today? Really? Or is that just that account is new?

```kql
IdentityInfo
| summarize CreationTime = max(AccountCreationTime), AccountUPN 
```

Oh... there are only 8 users? no way...

```kql
IdentityInfo
| where TimeGenerated > ago(14d)
| summarize CreationTime = max(AccountCreationTime) by AccountUPN 
```

That's more like it

```kql
let UserList = IdentityInfo
| where TimeGenerated > ago(14d)
| summarize CreationTime = max(AccountCreationTime) by AccountUPN  ;
SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| distinct Location,UserPrincipalName
| join kind=rightanti (
    SigninLogs
    | where TimeGenerated > ago(1d)
) on Location, UserPrincipalName
| lookup UserList on $left.UserPrincipalName == $right.AccountUPN
| where CreationTime < ago(1d)
| distinct Location, UserPrincipalName
```

Oh looks like a dormant account.... We could filter then away too... But let's keep them
But eh... Location isn't great here, let's use more precise  data, because one connection from BC from an account usually only used in ON is weird and won't show up here.
Let's explorer geohashing.

```kql
SigninLogs
| take 1
| extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
| extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| extend Geohash = geo_point_to_s2cell(Longitude, Latitude, 6)
``` 

🔗 [geo_point_to_s2cell documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/geo-point-to-s2cell-function)
Now let's use it.

```kql
let UserList = IdentityInfo
| where TimeGenerated > ago(14d)
| summarize CreationTime = max(AccountCreationTime) by AccountUPN  ;
SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
| extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| extend Geohash = geo_point_to_s2cell(Longitude, Latitude, 6)
| distinct UserPrincipalName,Geohash
| join kind=rightanti (
    SigninLogs
    | extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
    | extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
    | extend Geohash = geo_point_to_s2cell(Longitude, Latitude, 6)
    | where TimeGenerated > ago(1d)
) on UserPrincipalName, Geohash
| lookup UserList on $left.UserPrincipalName == $right.AccountUPN
| where CreationTime < ago(1d)
| distinct UserPrincipalName, Geohash
```

Can we display where they use to signin and then display the difference?

```kql
let UserList = IdentityInfo
| where TimeGenerated > ago(14d)
| summarize CreationTime = max(AccountCreationTime) by AccountUPN  ;
let KnownPlaces = SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| extend Place = strcat(LocationDetails.city,", ",LocationDetails.state, ", ", LocationDetails.countryOrRegion)
| summarize Places = make_set(Place) by UserPrincipalName ;
SigninLogs
| where TimeGenerated between (ago(90d)..ago(1d))
| extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
| extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| extend Geohash = geo_point_to_s2cell(Longitude, Latitude, 6)
| distinct UserPrincipalName,Geohash
| join kind=rightanti (
    SigninLogs
    | extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
    | extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
    | extend Geohash = geo_point_to_s2cell(Longitude, Latitude, 6)
    | extend Place = strcat(LocationDetails.city,", ",LocationDetails.state, ", ", LocationDetails.countryOrRegion)
    | where TimeGenerated > ago(1d)
) on UserPrincipalName, Geohash
| lookup UserList on $left.UserPrincipalName == $right.AccountUPN
| where CreationTime < ago(1d)
| lookup KnownPlaces on UserPrincipalName
| extend Places = iif( isempty(Places), "💤", Places)
| distinct UserPrincipalName, Geohash, KnownPlaces=tostring(Places), Place
```

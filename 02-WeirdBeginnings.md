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

Exploring that data we can see that many processes are created in the context of the machine. While it could be interresting for some threat detection, in our case proces created by the this actor will be in the context of a user. So we can filter out many process creation with the following:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where AccountType != "Machine"
```

# Invoke-FindMyACL


This simple script check only direct acl that the target user has


-- works with kerberos Ticket only..


-- can work from non domain-joined machine

```powershell.exe
Import-Module .\Invoke-FindMyACL.ps1
Invoke-FindMyACL -Domain domain.local -User shakedw
```

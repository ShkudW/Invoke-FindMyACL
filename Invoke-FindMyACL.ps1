function Invoke-FindMyACL {
    param(
        [string]$Domain,
        [string]$User
    )
    
    $UserSearcher = [adsisearcher]"(&(objectCategory=user)(sAMAccountName=$User))"
    $UserSearcher.SearchRoot = [ADSI]"LDAP://$Domain"
    $UR = $UserSearcher.FindOne()

    if (-not $UR) {
        write-error "Could not find user $User in domain $Domain."
        return
    }

    $UserSID = New-Object System.Security.Principal.SecurityIdentifier ($UR.Properties.objectsid[0] -as [byte[]]), 0

    write-host "[+] Searching for Interesting ACLs that $($User) has (SID: $($UserSID.Value) )" -ForegroundColor DarkYellow

    $SearchRoot = [ADSI]"LDAP://$Domain"
    $ObjectSearcher = [adsisearcher]$SearchRoot
    $ObjectSearcher.Filter = "(objectClass=*)"
    $ObjectSearcher.PageSize = 1000
    
    
    [void]$ObjectSearcher.PropertiesToLoad.Add("distinguishedname")
    [void]$ObjectSearcher.PropertiesToLoad.Add("name")
    [void]$ObjectSearcher.PropertiesToLoad.Add("objectclass")


    $AllObjects = $ObjectSearcher.FindAll()
    write-host "[+] OK.. looking at $($AllObjects.Count) objects that was found " -ForegroundColor DarkYellow

    $Results = @()

    foreach ($Obj in $AllObjects) {
    try {
        
        if (-not $Obj.Properties.Contains("distinguishedname")) {
             continue 
        }
        
        $DN = $Obj.Properties["distinguishedname"][0]
        
        $Name = if ($Obj.Properties.Contains("name")) {
             $Obj.Properties["name"][0] 
        } else {
             $DN.Split(',')[0].Replace("CN=","") 
        }

        $Class = if ($Obj.Properties.Contains("objectclass")) {
             $Obj.Properties["objectclass"][-1] 
        } else {
             "Unknown" 
        }

        $ADSIObject = [ADSI]"LDAP://$Domain/$DN"
        
        $ObjectSecurity = $ADSIObject.ObjectSecurity
        $Dacl = $ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])


        $MatchingRules = $Dacl | Where-Object { $_.IdentityReference -eq $UserSID }

        if ($MatchingRules) {
            foreach ($Rule in $MatchingRules) {
                $Results += [PSCustomObject]@{
                    ObjectName = $Name
                    ObjectType = $Class
                    DistinguishedName = $DN
                    ActiveDirectoryRights = $Rule.ActiveDirectoryRights
                    AccessControlType = $Rule.AccessControlType
                    IsInherited  = $Rule.IsInherited
                }
            }
        }
        }
        catch {
            continue
        }
    }

    if ($Results.Count -gt 0) {
        $Results
    
    } else {
        write-host "[-] No direct ACLs found for user $($User) on any objects." 
    }

}

Import-Module -Force "..\powerview.ps1"

# Unit tests for PowerView "net" cmdlets
#   These tests are currently linked to the way I have a test domain set up
#   proper mocking will be done later...


$ForeignDomain = 'testlab.local'
$ForeignDomainController = 'PRIMARY.testlab.local'
$DomainDN = "DC=$($ForeignDomain.Replace('.', ',DC='))"

Describe "Get-NetUser" {

    It "Should return local domain results" {
        if( (Get-NetUser | Measure-Object).count -lt 4 ) {
            Throw "Insufficient user objects returned"
        }
    }
    It "Should accept -UserName argument" {
        if( (Get-NetUser -UserName 'krbtgt' | Measure-Object).count -ne 1) {
            Throw "Insufficient user objects returned"
        }
    }   
    It "Should accept -Domain and -DomainController arguments" {
        if( ( Get-NetUser -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 4 ) {
            Throw "Insufficient user objects returned"
        }
    }
    It "Should accept -ADSPath argument" {
        if( ( Get-NetUser -ADSPath "CN=krbtgt,CN=Users,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Insufficient user objects returned"
        }
    }
    It "Should accept LDAP -ADSPath argument" {
        if( ( Get-NetUser -ADSPath "LDAP://CN=krbtgt,CN=Users,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Insufficient user objects returned"
        }
    }
    It "Should accept -Filter argument" {
        if( ( Get-NetUser -Filter '(samaccountname=krbtgt)' | Measure-Object).count -ne 1 ) {
            Throw "Incorrect user object returned"
        }
    }
    It "Should accept -SPN argument" {
        if( ((Get-NetUser -SPN | ?{$_.samaccountname -like 'krbtgt'}).samaccountname -ne 'krbtgt')) {
            Throw "Insufficient user objects returned"
        }
    }
    It "Should accept -AdminCount argument" {
        if( (Get-NetUser -AdminCount | Measure-Object).count -lt 3 ) {
            Throw "Insufficient user objects returned"
        }
    }
    It "Should accept -Unconstrained argument" {
        {Get-NetUser -Unconstrained} | Should Not Throw
    }
    It "Should accept -AllowDelegation argument" {
        if( (Get-NetUser -AllowDelegation | Measure-Object).count -lt 3 ) {
            Throw "Insufficient user objects returned"
        }
    }
    It "Should accept pipeline input" {
        if( ("krbtgt" | Get-NetUser | Measure-Object).count -ne 1) {
            Throw "Insufficient user objects returned"
        }
    }  
}


Describe "Add-NetUser" {
    # TODO: implement
}


Describe "Add-NetGroupUser" {
    # TODO: implement
}


Describe "Get-UserProperty" {
    It "Should get local user properties" {
        if ((Get-UserProperty | ?{$_.name -like 'whencreated'}).name -ne 'whencreated') {
            Throw "Could not retrieve 'whencreated' user property from local domain"
        }
    }
    It "Should accept -Properties argument"  {
        if ( (Get-UserProperty -Properties lastlogon,adspath | Measure-Object).count -lt 4 ) {
            Throw "Insufficient user properties returned"
        }
    }
    It "Should get remote user properties" {
        if ((Get-UserProperty -Domain $ForeignDomain | Where-Object {$_.name -like 'whencreated'}).name -ne 'whencreated') {
            Throw "Could not retrieve 'whencreated' user property from remote domain"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ((Get-UserProperty -Domain $ForeignDomain -DomainController $ForeignDomainController | Where-Object {$_.name -like 'whencreated'}).name -ne 'whencreated') {
            Throw "Could not retrieve 'whencreated' user property from remote domain"
        }
    }
}


Describe "Find-UserField" {
    It "Should not throw" {
        {Find-UserField} | Should not throw
    }
    It "Should accept -SearchTerm and -SearchField arguments"  {
        if ( (Find-UserField -SearchTerm 'Key Distribution' -SearchField description | Measure-Object).count -ne 1 ) {
            Throw "Insufficient user results returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments"  {
        if ( (Find-UserField -Domain $ForeignDomain -DomainController $ForeignDomainController -SearchTerm 'Key Distribution' | Measure-Object).count -ne 1 ) {
            Throw "Insufficient user results returned"
        }
    }
    It "Should accept pipeline input"  {
        if ( ('Key Distribution'  | Find-UserField | Measure-Object).count -ne 1 ) {
            Throw "Insufficient user results returned"
        }
    }
}


Describe "Get-UserEvent" {
    It "Should query local events" {
        if ( (Get-UserEvent | Measure-Object).count -lt 1 ) {
            Throw "Insufficient user events returned"
        }
    }
    It "Should accept -EventType argument" {
        if ( (Get-UserEvent -EventType logon | Measure-Object).count -lt 1 ) {
            Throw "Insufficient user events returned"
        }
    }
    It "Should accept -DateStart argument" {
        if ( (Get-UserEvent -DateStart (Get-Date).AddDays(-7) | Measure-Object).count -lt 1 ) {
            Throw "Insufficient user events returned"
        }
    }
    It "Should accept -ComputerName argument" {
        {Get-UserEvent -ComputerName "$env:computername" -EventType Logon -DateStart (Get-Date).AddDays(-1)} | Should not throw
    }
}

Describe "Get-ObjectAcl" {
    $DomainName = (Get-NetDomain).name
    $DomainDN = "DC=$($DomainName.Replace('.', ',DC='))"

    It "Should accept -SamAccountName argument" {
        if ( (Get-ObjectAcl -SamAccountName krbtgt | Measure-Object).count -lt 10 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -Name argument" {
        if ( (Get-ObjectAcl -Name krbtgt | Measure-Object).count -lt 10 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -DistinguishedName argument" {
        if ( (Get-ObjectAcl -DistinguishedName "CN=krbtgt,CN=Users,$DomainDN" | Measure-Object).count -lt 10 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -ResolveGUIDs argument" {
        if ( (Get-ObjectAcl -SamAccountName krbtgt -ResolveGUIDs | Measure-Object).count -lt 10 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -Filter argument" {
        if ( (Get-ObjectAcl -Filter '(samaccountname=krbtgt)' | Measure-Object).count -lt 10 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -ADSpath argument" {
        if ( (Get-ObjectAcl -ADSpath "CN=krbtgt,CN=Users,$DomainDN" | Measure-Object).count -lt 10 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -ADSprefix argument" {
        if ( (Get-ObjectAcl -ADSprefix 'CN=krbtgt,CN=Users' | Measure-Object).count -lt 10 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -RightsFilter argument" {
        if ( (Get-ObjectAcl -SamAccountName krbtgt -RightsFilter 'All' | Measure-Object).count -lt 1 ) {
            Throw "Insufficient ACLs for krbtgt returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ( (Get-ObjectAcl -SamAccountName krbtgt -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 1 ) {
            Throw "Insufficient ACLs for foreign krbtgt returned"
        }
    }
}


Describe "Add-ObjectAcl" {
    # TODO: implement
}


Describe "Get-GUIDMap" {
    It "Should build local GUID map" {
        $GUIDmap = Get-GUIDMap
        if($GUIDmap['bf967a0a-0de6-11d0-a285-00aa003049e2'] -ne 'Pwd-Last-Set') {
            Throw "Error retrieving GUID for 'Pwd-Last-Set'"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        $GUIDmap = Get-GUIDMap -Domain $ForeignDomain -DomainController $ForeignDomainController
        if($GUIDmap['bf967a0a-0de6-11d0-a285-00aa003049e2'] -ne 'Pwd-Last-Set') {
            Throw "Error retrieving GUID for 'Pwd-Last-Set'"
        }
    }
}


Describe "Get-NetComputer" {
    It "Should return local domain results" {
        if( (Get-NetComputer | Measure-Object).count -lt 2 ) {
            Throw "Insufficient computer objects returned"
        }
    }
    It "Should accept -ComputerName argument" {
        if( (Get-NetComputer -ComputerName "$($env:computername)*" | Measure-Object).count -ne 1 ) {
            Throw "Insufficient computer objects returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if( ( Get-NetComputer -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 2 ) {
            Throw "Insufficient computer objects returned"
        }
    }
    It "Should accept -ADSPath argument" {
        if( ( Get-NetComputer -ADSPath "OU=Domain Controllers,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Insufficient computer objects returned"
        }
    }
    It "Should accept LDAP -ADSPath argument" {
        if( ( Get-NetComputer -ADSPath "LDAP://OU=Domain Controllers,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Insufficient computer objects returned"
        }
    }
    It "Should accept -Filter argument" {
        # TODO: generalize this?
        if( ( Get-NetComputer -Filter "(samaccountname=$($env:computername)*)" | Measure-Object).count -ne 1 ) {
            Throw "Incorrect computer object returned"
        }
    }
    It "Should accept -Printers argument" {
        {Get-NetComputer -Printers} | Should Not Throw
    }

    It "Should accept -SPN argument" {
        if( ((Get-NetComputer -SPN "DNS*" | Measure-Object).count -ne 1 ) ) {
            Throw "Incorrect computer objects returned"
        }
    }
    It "Should accept -OperatingSystem argument" {
        if( (Get-NetComputer -OperatingSystem "*2012*" | Measure-Object).count -lt 1 )  {
            Throw "Insufficient computer objects returned"
        }
    }
    # It "Should accept -ServicePack argument" {

    # }
    It "Should accept -Ping argument" {
        if( ((Get-NetComputer -Ping | Measure-Object).count -lt 2 ) ) {
            Throw "Incorrect computer objects returned"
        }        
    }
    It "Should accept -FullData argument" {
        if( ((Get-NetComputer -FullData | Measure-Object).count -lt 2 ) ) {
            Throw "Incorrect computer objects returned"
        }        
    }
    It "Should accept -Unconstrained argument" {
        {Get-NetComputer -Unconstrained} | Should Not Throw
    }
    It "Should accept pipeline input" {
        if( ("$($env:computername)*" | Get-NetComputer | Measure-Object).count -ne 1) {
            Throw "Insufficient user objects returned"
        }
    }  
}


Describe "Get-ADObject" {
    It "Should not throw when getting all objects" {
        {Get-ADObject} | Should not throw
    }
    It "Should accept -SID argument" {
        if ( (Get-ADObject -SID 'S-1-5-21-2620891829-2411261497-1773853088-502' | Measure-Object).count -ne 1) {
            Throw "Incorrect AD object returned"
        }
    }
    It "Should not accept invalid -SID argument" {
        {Get-ADObject -SID 'S-1-5-21-2620891829-2411261497-1773853088'} | Should throw
    }
    It "Should accept -Name argument" {
        if ( (Get-ADObject -Name krbtgt | Measure-Object).count -ne 1 ) {
            Throw "Incorrect AD object returned"
        }
    }
    It "Should accept -SamAccountName argument" {
        if ( (Get-ADObject -SamAccountName krbtgt | Measure-Object).count -ne 1 ) {
            Throw "Incorrect AD object returned"
        }
    }
    It "Should accept -ADSpath argument" {
        if ( (Get-ADObject -ADSpath "CN=krbtgt,CN=Users,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Incorrect AD object returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ( (Get-ADObject -SamAccountName krbtgt -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 1 ) {
            Throw "Incorrect AD object returned"
        }
    }
    It "Should accept pipeline input"  {
        if ( ('S-1-5-21-2620891829-2411261497-1773853088-502' | Get-ADObject | Measure-Object).count -ne 1) {
            Throw "Incorrect AD object returned"
        }
    }
}


Describe "Get-ComputerProperty" {
    It "Should get local computer properties" {
        if ((Get-ComputerProperty | ?{$_.name -like 'whencreated'}).name -ne 'whencreated') {
            Throw "Could not retrieve 'whencreated' computer property from local domain"
        }
    }
    It "Should accept -Properties argument"  {
        if ( (Get-ComputerProperty -Properties lastlogon,adspath | Measure-Object).count -lt 2 ) {
            Throw "Insufficient computer properties returned"
        }
    }
    It "Should get remote computer properties" {
        if ((Get-ComputerProperty -Domain $ForeignDomain | Where-Object {$_.name -like 'whencreated'}).name -ne 'whencreated') {
            Throw "Could not retrieve 'whencreated' computer property from remote domain"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ((Get-ComputerProperty -Domain $ForeignDomain -DomainController $ForeignDomainController | Where-Object {$_.name -like 'whencreated'}).name -ne 'whencreated') {
            Throw "Could not retrieve 'whencreated' computer property from remote domain"
        }
    }
}


Describe "Find-ComputerField" {
    It "Should not throw" {
        {Find-ComputerField} | Should not throw
    }
    It "Should accept -SearchTerm and -SearchField arguments"  {
        if ( (Find-ComputerField -SearchTerm "$($env:computername)" -SearchField serviceprincipalname | Measure-Object).count -lt 1 ) {
            Throw "Insufficient user results returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments"  {
        if ( (Find-ComputerField -Domain $ForeignDomain -DomainController $ForeignDomainController -SearchTerm "PRIMARY" -SearchField serviceprincipalname | Measure-Object).count -ne 1 ) {
            Throw "Insufficient user results returned"
        }
    }
    It "Should accept -SearchTerm and -SearchField arguments"  {
        if ( ("$($env:computername)" | Find-ComputerField -SearchField serviceprincipalname | Measure-Object).count -ne 1 ) {
            Throw "Insufficient user results returned"
        }
    }
}


Describe "Get-NetOU" {
    It "Should not throw when getting all objects" {
        {Get-NetOU} | Should not throw
    }
    It "Should accept -OUName argument" {
        if ( (Get-NetOU -OUName 'Domain Controllers' | Measure-Object).count -ne 1) {
            Throw "Incorrect OU object returned"
        }
    }
    It "Should accept -GUID argument" {
        if ( (Get-NetOU -GUID '6AC1786C-016F-11D2-945F-00C04fB984F9' | Measure-Object).count -ne 1) {
            Throw "Incorrect OU object returned"
        }
    }
    It "Should accept -FullData argument" {
        if ( (Get-NetOU -OUName 'Domain Controllers' -FullData | Measure-Object).count -ne 1) {
            Throw "Incorrect OU object returned"
        }
    }
    It "Should accept -ADSpath argument" {
        if ( (Get-NetOU  -ADSpath "OU=Domain Controllers,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Incorrect AD object returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ( (Get-NetOU -OUName 'Domain Controllers' -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 1 ) {
            Throw "Incorrect AD object returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ('Domain Controllers' | Get-NetOU | Measure-Object).count -ne 1) {
            Throw "Incorrect OU object returned"
        }
    }
}


Describe "Get-NetSite" {
    It "Should not throw" {
        {Get-NetSite} | Should not throw
    }
    It "Should accept -SiteName argument" {
        {Get-NetSite -SiteName 'testing'} | Should not throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Get-NetSite -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
    It "Should accept -ADSpath argument" {
        {Get-NetSite -ADSpath 'testing'} | Should not throw
    }
    It "Should accept -GUID argument" {
        {Get-NetSite -GUID 'testing'} | Should not throw
    }
    It "Should accept -FullData argument" {
        {Get-NetSite -FullData} | Should not throw
    }
    It "Should accept pipeline input"  {
        {'testing' | Get-NetSite} | Should not throw
    }
}


Describe "Get-NetSubnet" {
    It "Should not throw" {
        {Get-NetSubnet} | Should not throw
    }
    It "Should accept -SiteName argument" {
        {Get-NetSubnet -SiteName 'testing'} | Should not throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Get-NetSubnet -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
    It "Should accept -ADSpath argument" {
        {Get-NetSubnet -ADSpath 'testing'} | Should not throw
    }
    It "Should accept -FullData argument" {
        {Get-NetSubnet -FullData} | Should not throw
    }
    It "Should accept pipeline input"  {
        {'testing' | Get-NetSubnet} | Should not throw
    }
}


Describe "Get-DomainSID" {
    It "Should return local domain SID" {
        if ((Get-DomainSID) -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+') {
            Throw "Invalid local domain sid returned"
        }
    }
    It "Should return remote domain SID" {
        if ((Get-DomainSID -Domain $ForeignDomain) -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+') {
            Throw "Invalid remote domain sid returned"
        }
    }
}


Describe "Get-NetGroup" {
    It "Should return local domain results" {
        if( (Get-NetGroup | Measure-Object).count -lt 4 ) {
            Throw "Insufficient group objects returned"
        }
    }
    It "Should accept -GroupName argument" {
        if( (Get-NetGroup -GroupName 'Domain Admins' | Measure-Object).count -ne 1) {
            Throw "Insufficient group objects returned"
        }
    }
    It "Should accept -SID argument" {
        if( (Get-NetGroup -SID 'S-1-5-21-2620891829-2411261497-1773853088-512' | Measure-Object).count -ne 1) {
            Throw "Incorrect group object returned"
        }
    }
    It "Should accept -UserName argument" {
        if( (Get-NetGroup -UserName 'Administrator' | Measure-Object).count -lt 2) {
            Throw "Insufficient group objects returned"
        }
    }
    It "Should accept -Filter argument" {
        if( ( Get-NetGroup -Filter '(samaccountname=Domain Admins)' | Measure-Object).count -ne 1 ) {
            Throw "Incorrect group object returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if( ( Get-NetGroup -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 4 ) {
            Throw "Insufficient group objects returned"
        }
    }
    It "Should accept -ADSPath argument" {
        if( ( Get-NetGroup -ADSPath "CN=Domain Admins,CN=Users,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Incorrect group object returned"
        }
    }
    It "Should accept LDAP -ADSPath argument" {
        if( ( Get-NetGroup -ADSPath "LDAP://CN=Domain Admins,CN=Users,$DomainDN" | Measure-Object).count -ne 1 ) {
            Throw "Incorrect group object returned"
        }
    }
    It "Should accept -AdminCount argument" {
        if( (Get-NetGroup -AdminCount | Measure-Object).count -lt 3 ) {
            Throw "Insufficient group objects returned"
        }
    }
    It "Should accept -FullData argument" {
        {Get-NetGroup -FullData} | Should Not Throw
    }
    It "Should accept pipeline input" {
        if( ('Domain Admins' | Get-NetGroup | Measure-Object).count -ne 1) {
            Throw "Insufficient group objects returned"
        }
    } 
}


Describe "Get-NetGroupMember" {
    It "Should return local domain results" {
        if( (Get-NetGroupMember | Measure-Object).count -lt 1 ) {
            Throw "Insufficient group member objects returned"
        }
    }
    It "Should accept -GroupName argument" {
        if( (Get-NetGroupMember -GroupName 'Domain Admins' | Measure-Object).count -lt 1) {
            Throw "Insufficient group member objects returned"
        }
    }
    It "Should accept -SID argument" {
        if( (Get-NetGroupMember -SID 'S-1-5-21-2620891829-2411261497-1773853088-512' | Measure-Object).count -lt 1) {
            Throw "Incorrect group member object returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if( ( Get-NetGroupMember -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 1 ) {
            Throw "Insufficient group member objects returned"
        }
    }
    It "Should accept -ADSPath argument" {
        {Get-NetGroupMember -ADSPath "CN=Domain Admins,CN=Users,$DomainDN"} | Should not throw
    }
    It "Should accept LDAP -ADSPath argument" {
        {Get-NetGroupMember -ADSPath "LDAP://CN=Domain Admins,CN=Users,$DomainDN"} | Should not throw
    }
    It "Should accept -FullData argument" {
        {Get-NetGroupMember -FullData} | Should Not Throw
    }
    It "Should accept -Recurse argument" {
        {Get-NetGroupMember -GroupName 'Domain Admins' -Recurse} | Should Not Throw
    }
    It "Should accept pipeline input" {
        if( ('Domain Admins' | Get-NetGroupMember | Measure-Object).count -lt 1) {
            Throw "Insufficient user objects returned"
        }
    } 
}


Describe "Get-NetFileServer" {
    It "Should not throw" {
        if ( (Get-NetFileServer | Measure-Object).count -lt 1) {
            "Insufficient file servers returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Get-NetFileServer -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
    It "Should accept -TargetUsers arguments" {
        {Get-NetFileServer -TargetUsers krbtgt,Administrator} | Should not throw
    }
}


Describe "Get-DFSshare" {
    It "Should not throw" {
        {Get-DFSshare} | Should not throw
    }
    It "Should accept '-Version 1' argument" {
        {Get-DFSshare -Version 1} | Should not throw
    }
    It "Should accept '-Version v2' argument" {
        {Get-DFSshare -Version v2} | Should not throw
    }
    It "Should accept '-Version all' argument" {
        {Get-DFSshare -Version all} | Should not throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Get-DFSshare -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
    It "Should accept -ADSpath argument" {
        {Get-DFSshare -ADSpath 'testing'} | Should not throw
    }
}


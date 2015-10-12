Import-Module -Force "..\powerview.ps1"

# Unit tests for PowerView GPO functionality
#   These tests are currently linked to the way I have a test domain set up
#   proper mocking will be done later...


$ForeignDomain = 'testlab.local'
$ForeignDomainController = 'PRIMARY.testlab.local'
$DomainDN = "DC=$($ForeignDomain.Replace('.', ',DC='))"

Describe "Get-GptTmpl" {
    It "Should not throw on parsing" {
        {Get-GptTmpl -GptTmplPath "\\$ForeignDomain\sysvol\$ForeignDomain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"} | Should not throw
    }
    It "Should parse a GptTmpl" {
        $Gpt = Get-GptTmpl -GptTmplPath "\\$ForeignDomain\sysvol\$ForeignDomain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        if( ($Gpt.KerberosPolicy.MaxServiceAge -ne 600 ) ) {
            Throw "Incorrectly parsed GptTmpl"
        }
    }
}


Describe "Get-NetGPO" {
    # Uses the "Default Domain Policy" GUID for testing
    #   {31B2F340-016D-11D2-945F-00C04FB984F9}
    $GUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

    It "Should not throw when getting all objects" {
        {Get-NetGPO} | Should not throw
    }
    It "Should accept -GPOname argument" {
        if ( (Get-NetGPO -GPOname $GUID | Measure-Object).count -ne 1) {
            Throw "Incorrect GPO object returned"
        }
    }
    It "Should accept -DisplayName argument" {
        if ( (Get-NetGPO -DisplayName 'Default Domain Policy' | Measure-Object).count -ne 1) {
            Throw "Incorrect GPO object returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ( (Get-NetGPO -GPOname $GUID -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 1 ) {
            Throw "Incorrect GPO object returned"
        }
    }
    It "Should accept -ADSpath argument" {
        if ( (Get-NetGPO -ADSpath "CN=$GUID,CN=Policies,CN=System,$DomainDN" | Measure-Object).count -ne 1) {
            Throw "Incorrect GPO object returned"
        }
    }
    It "Should accept LDAP -ADSpath argument" {
        if ( (Get-NetGPO -ADSpath "LDAP://CN=$GUID,CN=Policies,CN=System,$DomainDN" | Measure-Object).count -ne 1) {
            Throw "Incorrect GPO object returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ($GUID | Get-NetGPO | Measure-Object).count -ne 1) {
            Throw "Incorrect GPO object returned"
        }
    }
}


Describe "Get-NetGPOGroup" {
    # Uses the "Default Domain Policy" GUID for testing
    #   {31B2F340-016D-11D2-945F-00C04FB984F9}
    $GUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

    It "Should not throw" {
        {Get-NetGPOGroup} | Should not throw
    }
    It "Should accept -GPOname argument" {
        {Get-NetGPOGroup -GPOname $GUID} | Should not throw
    }

    It "Should accept -DisplayName argument" {
        {Get-NetGPOGroup -DisplayName 'LocalAdmins'} | Should not throw
    }
    It "Should accept -ADSpath argument" {
        {Get-NetGPOGroup -ADSpath "CN=$GUID,CN=Policies,CN=System,$DomainDN"} | Should not throw
    }
    It "Should accept LDAP -ADSpath argument" {
       {Get-NetGPOGroup -ADSpath "LDAP://CN=$GUID,CN=Policies,CN=System,$DomainDN"} | Should not throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Get-NetGPOGroup -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
}


Describe "Find-GPOLocation" {
    It "Default behavior should throw" {
        {Find-GPOLocation} | Should throw
    }
    It "Valid username should not throw" {
        {Find-GPOLocation -UserName 'krbtgt'} | Should not throw
    }
    It "Invalid username should throw" {
        {Find-GPOLocation -UserName 'aksdjfasdf'} | Should throw
    }
    It "Valid groupname should not throw" {
        {Find-GPOLocation -GroupName 'Domain Admins'} | Should not throw
    }
    It "Invalid groupname should throw" {
        {Find-GPOLocation -Groupname 'aksdjfasdf'} | Should throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Find-GPOLocation -UserName 'krbtgt' -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
    It "Should accept -LocalGroup argument" {
        {Find-GPOLocation -UserName 'krbtgt' -LocalGroup RDP} | Should not throw
    }
}


Describe "Find-GPOComputerAdmin" {
    It "No arguments should throw" {
        {Find-GPOComputerAdmin} | Should throw
    }    
    It "Valid ComputerName should not throw" {
        {Find-GPOComputerAdmin -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Invalid ComputerName should throw" {
        {Find-GPOComputerAdmin -ComputerName 'aksjdnfkaks'} | Should throw
    }
    It "Valid OUName should not throw" {
        {Find-GPOComputerAdmin -OUName "OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Invalid OUName should throw" {
        {Find-GPOComputerAdmin -OUName 'aksjdnfkaks'} | Should throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Find-GPOComputerAdmin -ComputerName "asdjkfnksjadfn" -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should throw
    }
    It "Should accept -Recurse argument" {
        {Find-GPOComputerAdmin -ComputerName "$env:computername.$env:userdnsdomain" -Recurse} | Should not throw
    }
    It "Should accept -LocalGroup argument" {
        {Find-GPOComputerAdmin -ComputerName "$env:computername.$env:userdnsdomain" -LocalGroup RDP} | Should not throw
    }
}


Describe "Get-DomainPolicy" {
    It "Default behavior should not throw" {
        {Get-DomainPolicy} | Should not throw
    }
    It "Should accept '-Source Domain' argument" {
        if ( (Get-DomainPolicy -Source Domain | Measure-Object).count -ne 1) {
            Throw "Incorrect domain policy returned"
        }
    }
    It "Should accept '-Source DC' argument" {
        if ( (Get-DomainPolicy -Source DC | Measure-Object).count -ne 1) {
            Throw "Incorrect domain controller policy returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ( (Get-DomainPolicy -Source DC -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -ne 1) {
            Throw "Incorrect domain controller policy returned"
        }
    }
    It "Should accept -ResolveSids argument" {
        if ( (Get-DomainPolicy -Source DC -ResolveSIDs | Measure-Object).count -ne 1) {
            Throw "Incorrect domain controller policy returned"
        }
    }
}


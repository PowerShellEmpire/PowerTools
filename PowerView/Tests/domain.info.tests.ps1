Import-Module -Force "..\powerview.ps1"

# Unit tests for PowerView domain query and trust cmdlets
#   These tests are currently linked to the way I have a test domain set up
#   proper mocking will be done later...

# Find-ForeignUser and Find-ForeignGroup definitely need proper mocking

$ForeignDomain = 'testlab.local'
$ForeignDomainController = 'PRIMARY.testlab.local'


Describe "Get-DomainSearcher" {
    # TODO: implement
}


Describe "Get-NetDomain" {
    It "Default settings should not throw" {
        {Get-NetDomain} | Should not throw
    }
    It "Getting a remote domain should not throw" {
        {Get-NetDomain -Domain $ForeignDomain} | Should not throw
    }
    It "Should accept pipeline input" {
        {$ForeignDomain | Get-NetDomain} | Should not throw
    }    
}


Describe "Get-NetForest" {
    It "Default settings should not throw" {
        {Get-NetForest} | Should not throw
    }
    It "Getting a remote forest should not throw" {
        {Get-NetForest -Forest $ForeignDomain} | Should not throw
    }
    It "Should accept pipeline input" {
        {$ForeignDomain | Get-NetForest} | Should not throw
    }    
}

Describe "Get-NetForestDomain" {
    It "Default settings should not throw" {
        {Get-NetForestDomain} | Should not throw
    }
    It "Getting a remote forest should not throw" {
        {Get-NetForestDomain -Forest $ForeignDomain} | Should not throw
    }
    It "Should accept -Domain filter" {
        {Get-NetForestDomain -Forest $ForeignDomain -Domain 'invalid.testlab.local'} | Should not throw
    }
    It "Should accept pipeline input" {
        {$ForeignDomain | Get-NetForestDomain} | Should not throw
    }    
}


Describe "Get-NetDomainController" {
    It "Default settings should not throw" {
        {Get-NetDomainController} | Should not throw
    }
    It "Getting a remote domain should not throw" {
        {Get-NetDomainController -Domain $ForeignDomain} | Should not throw
    }
    It "Should accept pipeline input" {
        {$ForeignDomain | Get-NetDomainController} | Should not throw
    }    
}


Describe "Get-NetDomainTrust" {
    It "Default settings should not throw" {
        {Get-NetDomainTrust} | Should not throw
    }
    It "Getting a remote domain should not throw" {
        {Get-NetDomainTrust -Domain $ForeignDomain} | Should not throw
    }
    It "Should accept -LDAP argument" {
        {Get-NetDomainTrust -Domain $ForeignDomain -LDAP} | Should not throw
    }
    It "Should accept -DomainController argument" {
        {Get-NetDomainTrust -Domain $ForeignDomain -DomainController $ForeignDomainController -LDAP} | Should not throw
    }
    It "Should accept pipeline input" {
        {$ForeignDomain | Get-NetDomainTrust} | Should not throw
    }    
}


Describe "Get-NetForestTrust" {
    It "Should enumerate current forest trusts" {
        {Get-NetForestTrust} | Should not throw
    }
    It "Should enumerate remote forest trusts" {
        {Get-NetForestTrust -Forest $ForeignDomain} | Should not throw
    }
    It "Should accept pipeline input" {
        {$ForeignDomain | Get-NetForestTrust } | Should not throw
    }
}


Describe "Find-ForeignUser" {
    # need to mock Get-NetUser and Invoke-MapDomainTrust
    It "Should return results for the local domain" {
        if ( (Find-ForeignUser | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should accept -UserName argument" {
        if ( (Find-ForeignUser -UserName matt.admin | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should accept -Recurse argument" {
        if ( (Find-ForeignUser -Recurse | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should accept -UserName and -Recurse arguments" {
        if ( (Find-ForeignUser -UserName matt.admin -Recurse | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Find-ForeignUser -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
}


Describe "Find-ForeignGroup" {
    # need to mock Get-NetGroup and Invoke-MapDomainTrust
    It "Should return results for the local domain" {
        if ( (Find-ForeignGroup | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should accept -GroupName argument" {
        if ( (Find-ForeignGroup -GroupName 'group3' | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should not throw on invalid -GroupName argument" {
        {Find-ForeignGroup -GroupName 'askdjnfkdsaf'} | Should not throw
    }
    It "Should accept -LDAP argument" {
        if ( (Find-ForeignGroup -LDAP | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }    
    It "Should accept -LDAP and -Recurse argument" {
        if ( (Find-ForeignGroup -LDAP -Recurse | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should accept -UserName and -Recurse arguments" {
        if ( (Find-ForeignGroup -GroupName 'group3' -Recurse | Measure-Object).count -lt 1) {
            Throw "Invalid results returned."
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Find-ForeignGroup -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
}


Describe "Invoke-MapDomainTrust" {
    It "Should enumerate all reachable domain trusts" {
        {Invoke-MapDomainTrust} | Should not throw
    }
    It "Should enumerate all reachable domain trusts through LDAP" {
        {Invoke-MapDomainTrust -LDAP} | Should not throw
    }
    It "Should enumerate all reachable domain trusts through a specified DC" {
        {Invoke-MapDomainTrust -LDAP -DomainController $ForeignDomainController} | Should not throw
    }
}

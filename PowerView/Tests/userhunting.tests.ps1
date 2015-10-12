Import-Module -Force "..\powerview.ps1"

# Unit tests for PowerView cmdlets that execute user-hunting functionality
#   These tests are currently linked to the way I have a test domain set up
#   proper mocking will be done later...


$ForeignDomain = 'testlab.local'
$ForeignDomainController = 'PRIMARY.testlab.local'
$DomainDN = "DC=$($ForeignDomain.Replace('.', ',DC='))"


Describe "Invoke-UserHunter" {
    It "Default behavior" {
        {Invoke-UserHunter} | Should not throw
    }
    It "Should accept -ComputerName argument" {
        if ( (Invoke-UserHunter -ShowAll -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerFile argument" {
        "$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain" | Out-File -Encoding ASCII targets.txt
        if ( (Invoke-UserHunter -ComputerFile ".\targets.txt" -ShowAll | Measure-Object).count -lt 1) {
            Remove-Item -Force ".\targets.txt"
            Throw "Insuffient results returned"
        }
        else {
            Remove-Item -Force ".\targets.txt"
        }
    }
    It "Should accept -ComputerFilter argument" {
        {Invoke-UserHunter -ComputerFilter "(dnshostname=$($env:computername)*)"}| Should not throw
    }
    It "Should accept -ComputerADSpath argument" {
        {Invoke-UserHunter -ComputerADSpath "OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept LDAP -ComputerADSpath argument" {
        {Invoke-UserHunter -ComputerADSpath "LDAP://OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept -GroupName argument" {
        {Invoke-UserHunter -GroupName 'Domain Admins'} | Should not throw
    }
    It "Should accept -TargetServer argument" {
        {Invoke-UserHunter -TargetServer "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -UserName argument" {
        if ( (Invoke-UserHunter -UserName $env:USERNAME | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -UserFilter argument" {
        if ( (Invoke-UserHunter -UserFilter "(samaccountname=$($env:USERNAME))" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -UserADSpath argument" {
        if ( (Invoke-UserHunter -UserADSpath "CN=$($env:USERNAME),CN=Users,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Default accept LDAP -UserADSpath argument" {
        if ( (Invoke-UserHunter -UserADSpath "LDAP://CN=$($env:USERNAME),CN=Users,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -UserFile argument" {
        "$env:USERNAME" | Out-File -Encoding ASCII target_users.txt
        if ( (Invoke-UserHunter -UserFile ".\target_users.txt" | Measure-Object).count -lt 1) {
            Remove-Item -Force ".\target_users.txt"
            Throw "Insuffient results returned"
        }
        else {
            Remove-Item -Force ".\target_users.txt"
        }
    }
    It "Should accept -StopOnSuccess flag" {
        if ( (Invoke-UserHunter -UserName $env:USERNAME -StopOnSuccess | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -NoPing flag" {
        if ( (Invoke-UserHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserName $env:USERNAME -NoPing | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-UserHunter -UserName $env:USERNAME -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername.$env:userdnsdomain", "$env:computername.$env:userdnsdomain") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Invoke-UserHunter -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object} | Should not throw
    }
    It "Should accept -SearchForest argument" {
        if ( (Invoke-UserHunter -SearchForest -ShowAll | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Stealth argument" {
        {Invoke-UserHunter -Stealth} | Should not throw
    }
    It "Should accept -StealthSource argument" {
        {Invoke-UserHunter -Stealth -StealthSource File} | Should not throw
    }
    It "Should accept -Threads argument" {
        Start-Sleep -Milliseconds 500
        if ( (Invoke-UserHunter -Threads 10 -ShowAll | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ("$env:computername.$env:userdnsdomain" | Invoke-UserHunter | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Invoke-StealthUserHunter" {
    # simple test of the splatting
    It "Should accept splatting for Invoke-UserHunter" {
        {Invoke-StealthUserHunter -ShowAll -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
}


Describe "Invoke-ProcessHunter" {
    It "Default behavior" {
        {Invoke-ProcessHunter} | Should not throw
    }
    It "Should accept -ComputerName and -UserName arguments" {
        if ( (Invoke-ProcessHunter -UserName $env:USERNAME -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerFile argument" {
        "$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain" | Out-File -Encoding ASCII targets.txt
        if ( (Invoke-ProcessHunter -ComputerFile ".\targets.txt" -UserName $env:USERNAME | Measure-Object).count -lt 1) {
            Remove-Item -Force ".\targets.txt"
            Throw "Insuffient results returned"
        }
        else {
            Remove-Item -Force ".\targets.txt"
        }
    }
    It "Should accept -ComputerFilter argument" {
        {Invoke-ProcessHunter -UserName $env:USERNAME -ComputerFilter "(dnshostname=$($env:computername)*)"} | Should not throw
    }
    It "Should accept -ComputerADSpath argument" {
        {Invoke-ProcessHunter -ComputerADSpath "OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept LDAP -ComputerADSpath argument" {
        {Invoke-ProcessHunter -ComputerADSpath "LDAP://OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept -ProcessName argument" {
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername.$env:userdnsdomain" -ProcessName powershell | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -GroupName argument" {
        {Invoke-ProcessHunter -GroupName 'Domain Admins' -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -TargetServer argument" {
        {Invoke-ProcessHunter -TargetServer "$env:computername.$env:userdnsdomain" -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -UserFilter argument" {
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserFilter "(samaccountname=$($env:USERNAME))" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -UserADSpath argument" {
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserADSpath "CN=$($env:USERNAME),CN=Users,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Default accept LDAP -UserADSpath argument" {
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserADSpath "LDAP://CN=$($env:USERNAME),CN=Users,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -UserFile argument" {
        "$env:USERNAME" | Out-File -Encoding ASCII target_users.txt
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserFile ".\target_users.txt" | Measure-Object).count -lt 1) {
            Remove-Item -Force ".\target_users.txt"
            Throw "Insuffient results returned"
        }
        else {
            Remove-Item -Force ".\target_users.txt"
        }
    }
    It "Should accept -StopOnSuccess flag" {
        if ( (Invoke-ProcessHunter -UserName $env:USERNAME -StopOnSuccess | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -NoPing flag" {
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserName $env:USERNAME -NoPing | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-ProcessHunter -UserName $env:USERNAME -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername.$env:userdnsdomain", "$env:computername.$env:userdnsdomain") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Invoke-ProcessHunter -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object} | Should not throw
    }
    It "Should accept -SearchForest argument" {
        if ( (Invoke-ProcessHunter -SearchForest -ShowAll | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Threads argument" {
        Start-Sleep -Milliseconds 500
        if ( (Invoke-ProcessHunter -Threads 10 -UserName $env:USERNAME | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ("$env:computername.$env:userdnsdomain" | Invoke-ProcessHunter -UserName $env:USERNAME | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Invoke-EventHunter" {
    # It "Default behavior" {
    #     {Invoke-EventHunter} | Should not throw
    # }

    It "Should accept -ComputerName and -UserName arguments" {
        {Invoke-EventHunter -UserName $env:USERNAME -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -ComputerFile and -UserName arguments" {
        "$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain" | Out-File -Encoding ASCII targets.txt
        {Invoke-EventHunter -ComputerFile ".\targets.txt" -UserName $env:USERNAME} | Should not throw
        Remove-Item -Force ".\targets.txt"
    }
    It "Should accept -ComputerFilter argument" {
        {Invoke-EventHunter -UserName $env:USERNAME -ComputerFilter "(dnshostname=$($env:computername)*)"} | Should not throw
    }
    It "Should accept -ComputerADSpath argument" {
        {Invoke-EventHunter -ComputerADSpath "OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept LDAP -ComputerADSpath argument" {
        {Invoke-EventHunter -ComputerADSpath "LDAP://OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept -GroupName argument" {
        {Invoke-EventHunter -GroupName 'Domain Admins' -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -TargetServer argument" {
        {Invoke-EventHunter -TargetServer "$env:computername.$env:userdnsdomain" -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -UserFilter argument" {
        {Invoke-EventHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserFilter "(samaccountname=$($env:USERNAME))"} | Should not throw
    }
    It "Should accept -UserADSpath argument" {
        {Invoke-EventHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserADSpath "CN=$($env:USERNAME),CN=Users,$DomainDN"} | Should not throw
    }
    It "Default accept LDAP -UserADSpath argument" {
        {Invoke-EventHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserADSpath "LDAP://CN=$($env:USERNAME),CN=Users,$DomainDN"} | Should not throw
    }
    It "Should accept -UserFile argument" {
        "$env:USERNAME" | Out-File -Encoding ASCII target_users.txt
        {Invoke-EventHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserFile ".\target_users.txt" } | Should not throw
        Remove-Item -Force ".\target_users.txt"
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Invoke-EventHunter -Domain $ForeignDomain -DomainController $ForeignDomainController -SearchDays 1 | Measure-Object} | Should not throw
    }
    # It "Should accept -SearchForest argument" {
    #     if ( (Invoke-ProcessHunter -SearchForest -ShowAll | Measure-Object).count -lt 1) {
    #         Throw "Insuffient results returned"
    #     }
    # }
    It "Should accept -Threads argument" {
        Start-Sleep -Milliseconds 500
        {Invoke-EventHunter -ComputerName "$env:computername.$env:userdnsdomain" -Threads 10 -UserName $env:USERNAME} | Should not throw
    }
    It "Should accept pipeline input" {
        {"$env:computername.$env:userdnsdomain" | Invoke-EventHunter -ComputerName "$env:computername.$env:userdnsdomain" -UserName $env:USERNAME } | Should not throw
    }
}

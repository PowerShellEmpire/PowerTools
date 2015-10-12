Import-Module -Force "..\powerview.ps1"

# Unit tests for PowerView cmdlets that misc. 'meta-functionality' (like share-finding)
#   These tests are currently linked to the way I have a test domain set up
#   proper mocking will be done later...


$ForeignDomain = 'testlab.local'
$ForeignDomainController = 'PRIMARY.testlab.local'
$DomainDN = "DC=$($ForeignDomain.Replace('.', ',DC='))"


Describe "Invoke-ShareFinder" {
    It "Default behavior" {
        if ( (Invoke-ShareFinder | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerName argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerFile argument" {
        "$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain" | Out-File -Encoding ASCII targets.txt
        if ( (Invoke-ShareFinder -ComputerFile ".\targets.txt" | Measure-Object).count -lt 1) {
            Remove-Item -Force ".\targets.txt"
            Throw "Insuffient results returned"
        }
        else {
            Remove-Item -Force ".\targets.txt"
        }
    }
    It "Should accept -ComputerFilter argument" {
        if ( (Invoke-ShareFinder -ComputerFilter "(dnshostname=$($env:computername)*)" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerADSpath argument" {
        if ( (Invoke-ShareFinder -ComputerADSpath "OU=Domain Controllers,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept LDAP -ComputerADSpath argument" {
        if ( (Invoke-ShareFinder -ComputerADSpath "LDAP://OU=Domain Controllers,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ExcludeStandard argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername.$env:userdnsdomain" -ExcludeStandard | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ExcludePrint argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername.$env:userdnsdomain" -ExcludePrint | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ExcludeIPC argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername.$env:userdnsdomain" -ExcludeIPC | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -CheckShareAccess argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername.$env:userdnsdomain" -CheckShareAccess | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -CheckAdmin argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername.$env:userdnsdomain" -CheckAdmin | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -NoPing argument" {
        if ( (Invoke-ShareFinder -NoPing -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-ShareFinder -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername.$env:userdnsdomain", "$env:computername.$env:userdnsdomain") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ( (Invoke-ShareFinder -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -SearchForest argument" {
        if ( (Invoke-ShareFinder -SearchForest | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Threads argument" {
        {Invoke-ShareFinder -Threads 10} | Should not throw
    }
    It "Should accept pipeline input" {
        if ( ("$env:computername.$env:userdnsdomain" | Invoke-ShareFinder | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Invoke-FileFinder" {
    It "Default behavior" {
        {Invoke-FileFinder} | Should not throw
    }
    It "Should accept -ComputerName argument" {
        {Invoke-FileFinder -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -ComputerFile argument" {
        "$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain" | Out-File -Encoding ASCII targets.txt        
        {Invoke-FileFinder -ComputerFile ".\targets.txt"} | Should not throw
        Remove-Item -Force ".\targets.txt"
    }
    It "Should accept -ComputerFilter argument" {
        {Invoke-FileFinder -ComputerFilter "(dnshostname=$($env:computername)*)"} | Should not throw
    }
    It "Should accept -ComputerADSpath argument" {
        {Invoke-FileFinder -ComputerADSpath "OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept LDAP -ComputerADSpath argument" {
        {Invoke-FileFinder -ComputerADSpath "LDAP://OU=Domain Controllers,$DomainDN"} | Should not throw
    }
    It "Should accept -ShareList argument" {
        "\\$($env:computername)\\IPC$" | Out-File -Encoding ASCII shares.txt
        {Invoke-FileFinder -ShareList ".\shares.txt"} | Should not throw
        Remove-Item -Force ".\shares.txt"
    }
    It "Should accept -Terms argument" {
        {Invoke-FileFinder -Terms secret,testing -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -OfficeDocs argument" {
        {Invoke-FileFinder -OfficeDocs -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -FreshEXEs argument" {
        {Invoke-FileFinder -FreshEXEs -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -LastAccessTime argument" {
        {Invoke-FileFinder -LastAccessTime "01/01/2000" -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -LastWriteTime argument" {
        {Invoke-FileFinder -LastWriteTime "01/01/2000" -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -ExcludeFolders argument" {
        {Invoke-FileFinder -ExcludeFolders -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -ExcludeHidden argument" {
        {Invoke-FileFinder -ExcludeHidden -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -CreationTime argument" {
        {Invoke-FileFinder -CreationTime "01/01/2000" -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -OutFile argument" {
        Invoke-FileFinder -OutFile "found_files.csv"
        ".\found_files.csv" | Should Exist
        Remove-Item -Force .\found_files.csv
    }
    It "Should accept -NoPing argument" {
        {Invoke-FileFinder -NoPing -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept -Delay and -Jitter arguments" {
        {Invoke-FileFinder -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain")} | Should not throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Invoke-FileFinder -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not throw
    }
    It "Should accept -SearchForest argument" {
        {Invoke-FileFinder -SearchForest} | Should not throw
    }
    It "Should accept -Threads argument" {
        {Invoke-FileFinder -Threads 10} | Should not throw
    }
    It "Should accept pipeline input" {
        {"$env:computername.$env:userdnsdomain" | Invoke-FileFinder} | Should not throw
    }
}


Describe "Find-LocalAdminAccess" {
    It "Default behavior" {
        if ( (Find-LocalAdminAccess | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerName argument" {
        if ( (Find-LocalAdminAccess -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerFile argument" {
        "$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain" | Out-File -Encoding ASCII targets.txt
        if ( (Find-LocalAdminAccess -ComputerFile ".\targets.txt" | Measure-Object).count -lt 1) {
            Remove-Item -Force ".\targets.txt"
            Throw "Insuffient results returned"
        }
        else {
            Remove-Item -Force ".\targets.txt"
        }
    }
    It "Should accept -ComputerFilter argument" {
        if ( (Find-LocalAdminAccess -ComputerFilter "(dnshostname=$($env:computername)*)" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerADSpath argument" {
        {Find-LocalAdminAccess -ComputerADSpath "OU=Domain Controllers,$DomainDN"} | Should not Throw
    }
    It "Should accept LDAP -ComputerADSpath argument" {
        {Find-LocalAdminAccess -ComputerADSpath "LDAP://OU=Domain Controllers,$DomainDN"} | Should not Throw
    }
    It "Should accept -NoPing argument" {
        if ( (Find-LocalAdminAccess -NoPing -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Find-LocalAdminAccess -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
       {Find-LocalAdminAccess -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should not Throw
    }
    It "Should accept -SearchForest argument" {
        if ( (Find-LocalAdminAccess -SearchForest | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Threads argument" {
        {Find-LocalAdminAccess -Threads 10} | Should not throw
    }
    It "Should accept pipeline input" {
        if ( ("$env:computername.$env:userdnsdomain" | Find-LocalAdminAccess | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Get-ExploitableSystem" {
    It "Should return local domain results" {
        {Get-ExploitableSystem} | Should Not Throw
    }
    It "Should accept -ComputerName argument" {
        {Get-ExploitableSystem -ComputerName "$($env:computername)*"} | Should Not Throw
    }
    It "Should accept -Domain and -DomainController arguments" {
        {Get-ExploitableSystem -Domain $ForeignDomain -DomainController $ForeignDomainController} | Should Not Throw
    }
    It "Should accept -ADSPath argument" {
        {Get-ExploitableSystem -ADSPath "OU=Domain Controllers,$DomainDN"} | Should Not Throw
    }
    It "Should accept LDAP -ADSPath argument" {
        {Get-ExploitableSystem -ADSPath "LDAP://OU=Domain Controllers,$DomainDN"} | Should Not Throw
    }
    It "Should accept -Filter argument" {
        {Get-ExploitableSystem -Filter "(samaccountname=$($env:computername)*)"} | Should Not Throw
    }
    It "Should accept -SPN argument" {
        {Get-ExploitableSystem -SPN "DNS*"} | Should Not Throw
    }
    It "Should accept -OperatingSystem argument" {
        {Get-ExploitableSystem -OperatingSystem "*2012*"} | Should Not Throw
    }
    # It "Should accept -ServicePack argument" {

    # }
    It "Should accept -Ping argument" {
        {Get-ExploitableSystem -Ping} | Should Not Throw
    }
    It "Should accept -Unconstrained argument" {
        {Get-ExploitableSystem -Unconstrained} | Should Not Throw
    }
    It "Should accept pipeline input" {
        {"$($env:computername)*" | Get-ExploitableSystem} | Should Not Throw
    }
}


Describe "Invoke-EnumerateLocalAdmin" {
    It "Default behavior" {
        if ( (Invoke-EnumerateLocalAdmin | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerName argument" {
        if ( (Invoke-EnumerateLocalAdmin -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerFile argument" {
        "$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain" | Out-File -Encoding ASCII targets.txt
        if ( (Invoke-EnumerateLocalAdmin -ComputerFile ".\targets.txt" | Measure-Object).count -lt 1) {
            Remove-Item -Force ".\targets.txt"
            Throw "Insuffient results returned"
        }
        else {
            Remove-Item -Force ".\targets.txt"
        }
    }
    It "Should accept -ComputerFilter argument" {
        if ( (Invoke-EnumerateLocalAdmin -ComputerFilter "(dnshostname=$($env:computername)*)" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ComputerADSpath argument" {
        if ( (Invoke-EnumerateLocalAdmin -ComputerADSpath "OU=Domain Controllers,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept LDAP -ComputerADSpath argument" {
        if ( (Invoke-EnumerateLocalAdmin -ComputerADSpath "LDAP://OU=Domain Controllers,$DomainDN" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -NoPing argument" {
        if ( (Invoke-EnumerateLocalAdmin -NoPing -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-EnumerateLocalAdmin -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername.$env:userdnsdomain","$env:computername.$env:userdnsdomain") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Outfile argument" {
        Invoke-EnumerateLocalAdmin -OutFile "local_admins.csv"
        ".\local_admins.csv" | Should Exist
        Remove-Item -Force .\local_admins.csv
    }
    It "Should accept -TrustGroups argument" {
        if ( (Invoke-EnumerateLocalAdmin -TrustGroups | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Domain and -DomainController arguments" {
        if ( (Invoke-EnumerateLocalAdmin -Domain $ForeignDomain -DomainController $ForeignDomainController | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -SearchForest argument" {
        if ( (Invoke-EnumerateLocalAdmin -SearchForest | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Threads argument" {
        {Invoke-EnumerateLocalAdmin -Threads 10} | Should not throw
    }
}

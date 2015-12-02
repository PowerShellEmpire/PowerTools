Import-Module -Force "..\PowerView.ps1"


# TODO: with mocking:
#     Copy-ClonedFile
#     Convert-NameToSid
#     Convert-SidToName
#     Convert-NT4toCanonical
#     Convert-LDAPProperty
#     Find-InterestingFile
#     All domain info functions


# Get the local IP address for later testing
$IPregex = "(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
$LocalIP = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -match $IPregex}).ipaddress[0]


########################################################
#
# Helper functions.
#
########################################################

Describe 'Export-PowerViewCSV' {
    It 'Should not throw and should produce .csv output.' {
        {Get-Process | Export-PowerViewCSV -OutFile process_test.csv} | Should Not Throw
        '.\process_test.csv' | Should Exist
        Remove-Item -Force .\process_test.csv        
    }
}


Describe 'Set-MacAttribute' {
    BeforeEach {
        New-Item MacAttribute.test.txt -Type file
    }
    AfterEach {
        Remove-Item -Force MacAttribute.test.txt
    }
    It 'Should clone MAC attributes of existing file' {
        Set-MacAttribute -FilePath MacAttribute.test.txt -All '01/01/2000 12:00 am'
        $File = (Get-Item MacAttribute.test.txt)
        $Date = Get-Date -Date '2000-01-01 00:00:00'
        
        if ($File.LastWriteTime -ne $Date) {
            Throw 'File LastWriteTime does not match'
        }
        elseif($File.LastAccessTime -ne $Date) {
            Throw 'File LastAccessTime does not match'
        }
        elseif($File.CreationTime -ne $Date) {
            Throw 'File CreationTime does not match'
        }
    }
}


Describe 'Get-IPAddress' {
    $IPregex = "(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
    It 'Should return local IP address' {
        if( $(Get-IPAddress) -notmatch $IPRegex ) {
            Throw 'Invalid local IP address returned'
        }
    }
    It 'Should accept -ComputerName argument' {
        if( $(Get-IPAddress -ComputerName $env:COMPUTERNAME) -notmatch $IPRegex ) {
            Throw 'Invalid -ComputerName IP address returned'
        }
    }
}


Describe 'Get-Proxy' {
    # TODO: implement more proxy testing
    It 'Should not throw' {
        {Get-Proxy} | Should Not Throw
    }
}


Describe 'Get-NameField' {
    It 'Should extract dnshostname field from custom object' {
        $Object = New-Object -TypeName PSObject -Property @{'dnshostname' = 'testing1'}
        if ( (Get-NameField -Object $Object).dnshostname -ne 'testing1') {
            Throw "'dnshostname' field not parsed correctly"
        }
    }
    It 'Should extract name field from custom object' {
        $Object = New-Object -TypeName PSObject -Property @{'name' = 'testing2'}
        if ( (Get-NameField -Object $Object).name -ne 'testing2') {
            Throw "'name' field not parsed correctly"
        }
    } 
    It 'Should handle plaintext strings' {
        if ( (Get-NameField -Object 'testing3') -ne 'testing3') {
            Throw 'Plaintext string not parsed correctly'
        }
    } 
    It 'Should accept pipeline input' {
        $Object = New-Object -TypeName PSObject -Property @{'dnshostname' = 'testing4'}
        if ( ($Object | Get-NameField).dnshostname -ne 'testing4') {
            Throw 'Pipeline input not processed correctly'
        }
    }
}


Describe 'Invoke-ThreadedFunction' {
    It "Should allow threaded ping" {
        $Hosts = ,"localhost" * 100
        $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
        $Hosts = Invoke-ThreadedFunction -NoImports -ComputerName $Hosts -ScriptBlock $Ping -Threads 20
        if($Hosts.length -ne 100) {
            Throw 'Error in using Invoke-ThreadedFunction to ping localhost'
        }
    }
}


########################################################
#
# 'API' based functions
#
########################################################

Describe "Get-NetLocalGroup" {
    It "Should return results for local machine administrators" {
        if ( (Get-NetLocalGroup | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should return results for listing local groups" {
        if ( (Get-NetLocalGroup -ListGroups | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    # TODO: -ComputerList
    It "Should accept -GroupName argument" {
        {Get-NetLocalGroup -GroupName "Remote Desktop Users"} | Should not throw
    }
    It "Should accept -Recurse argument" {
        if ( (Get-NetLocalGroup -Recurse | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept FQDN -ComputerName argument" {
        if ( (Get-NetLocalGroup -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetLocalGroup -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetLocalGroup -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( "$env:computername.$env:userdnsdomain" | Get-NetLocalGroup | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
}


Describe "Get-NetShare" {
    It "Should return results for the local host" {
        if ( (Get-NetShare | Measure-Object).count -lt 1) {
            Throw "Incorrect share results returned"
        }
    }
    It "Should accept FQDN -ComputerName argument" {
        if ( (Get-NetShare -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetShare -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetShare -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect share results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( "$env:computername.$env:userdnsdomain" | Get-NetShare | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
}


Describe "Get-NetLoggedon" {
    It "Should return results for the local host" {
        if ( (Get-NetLoggedon | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept FQDN -ComputerName argument" {
        if ( (Get-NetLoggedon -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }        
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetLoggedon -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetLoggedon -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }        
    }
    It "Should accept pipeline input" {
        if ( ( "$env:computername.$env:userdnsdomain" | Get-NetLoggedon | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
}


Describe "Get-NetSession" {
    It "Should return results for the local host" {
        if ( (Get-NetSession | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept FQDN -ComputerName argument" {
        if ( (Get-NetSession -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetSession -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetSession -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept the -UserName argument" {
        {Get-NetSession -UserName 'Administrator'} | Should not throw
    }
    It "Should accept pipeline input" {
        {"$env:computername.$env:userdnsdomain" | Get-NetSession} | Should not throw
    }
}


Describe "Get-NetRDPSession" {
    It "Should return results for the local host" {
        if ( (Get-NetRDPSession | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept FQDN -ComputerName argument" {
        if ( (Get-NetRDPSession -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetRDPSession -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetRDPSession -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept pipeline input" {
        {"$env:computername.$env:userdnsdomain" | Get-NetRDPSession} | Should not throw
    }
}


Describe "Invoke-CheckLocalAdminAccess" {
    It "Should not throw for localhost" {
        {Invoke-CheckLocalAdminAccess} | Should not throw
    }
    It "Should accept FQDN -ComputerName argument" {
        {Invoke-CheckLocalAdminAccess -ComputerName "$env:computername.$env:userdnsdomain"} | Should not throw
    }
    It "Should accept NETBIOS -ComputerName argument" {
        {Invoke-CheckLocalAdminAccess -ComputerName "$env:computername"} | Should not throw
    }
    It "Should accept IP -ComputerName argument" {
        {Invoke-CheckLocalAdminAccess -ComputerName $LocalIP} | Should not throw
    }
    It "Should accept pipeline input" {
        {"$env:computername.$env:userdnsdomain" | Invoke-CheckLocalAdminAccess} | Should not throw
    }
}


Describe "Get-LastLoggedOn" {
    It "Should return results for the local host" {
        if ( (Get-LastLoggedOn | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept FQDN -ComputerName argument" {
        if ( (Get-LastLoggedOn -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-LastLoggedOn -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-LastLoggedOn -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept pipeline input" {
        {"$env:computername.$env:userdnsdomain" | Get-LastLoggedOn} | Should not throw
    }
}


Describe "Get-NetProcess" {
    It "Should return results for the local host" {
        if ( (Get-NetProcess | Measure-Object).count -lt 1) {
            Throw "Incorrect process results returned"
        }
    }
    It "Should accept FQDN -ComputerName argument" {
        if ( (Get-NetProcess -ComputerName "$env:computername.$env:userdnsdomain" | Measure-Object).count -lt 1) {
            Throw "Incorrect process results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetProcess -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect process results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetProcess -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect process results returned"
        }
    }
    # TODO: RemoteUserName/RemotePassword
    It "Should accept pipeline input" {
        {"$env:computername.$env:userdnsdomain" | Get-NetProcess} | Should not throw
    }
}

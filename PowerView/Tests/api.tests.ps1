Import-Module -Force "..\powerview.ps1"

# Unit tests for PowerView cmdlets that utilize API or WMI functionality
#   These should run correctly regardless of domain setup



# Get the local IP address for later testing
$IPregex="(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
$LocalIP = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -match $IPregex}).ipaddress[0]


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

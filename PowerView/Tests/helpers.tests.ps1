Import-Module -Force "..\powerview.ps1"

# Unit tests for PowerView "helper" cmdlets
#   These tests are currently linked to the way I have a test domain set up
#   proper mocking will be done later...


Describe "Export-PowerViewCSV" {
    It "should not throw" {
        {Get-Process | Export-PowerViewCSV -OutFile process_test.csv} | Should Not Throw
    }
    It "should output a .csv" {
        ".\process_test.csv" | Should Exist
        Remove-Item -Force .\process_test.csv
    }
}


Describe "Set-MacAttribute" {
    BeforeEach {
        New-Item MacAttribute.test.txt -type file
    }
    AfterEach {
        Remove-Item -Force MacAttribute.test.txt
    }
    It "should clone attribute" {
        Set-MacAttribute -FilePath MacAttribute.test.txt -All "01/01/2000 12:00 am"
        $File = (Get-Item MacAttribute.test.txt)
        $Date = Get-Date -Date "2000-01-01 00:00:00"
        
        if ($File.LastWriteTime -ne $Date) {
            Throw 'File LastWriteTime does not match!'
        }
        elseif($File.LastAccessTime -ne $Date) {
            Throw 'File LastAccessTime does not match!'
        }
        elseif($File.CreationTime -ne $Date) {
            Throw 'File CreationTime does not match!'
        }
    }
}


Describe "Copy-ClonedFile" {
    # TODO: implement
}


Describe "Get-IPAddress" {
    $IPregex="(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
    It "Should return local IP address" {
        if( $(Get-IPAddress) -notmatch $IPRegex ) {
            Throw "Invalid local IP address returned"
        }
    }
    It "Should accept -ComputerName argument" {
        if( $(Get-IPAddress -ComputerName $env:COMPUTERNAME) -notmatch $IPRegex ) {
            Throw "Invalid -ComputerName IP address returned"
        }
    }
}


Describe "Convert-NameToSid" {
    It "Should convert local domain name to sid" {
        Convert-NameToSid -ObjectName 'krbtgt' | Should match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+'
    }
    It "Should convert remote domain name to sid" {
        Convert-NameToSid -ObjectName 'krbtgt' -Domain 'testlab.local' | Should match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+'
    }
    It "Should convert 'domain\user' to sid" {
        Convert-NameToSid -ObjectName 'TESTLAB\krbtgt' | Should match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+'
    }
    It "Should accept pipeline input" {
        'TESTLAB\krbtgt' | Convert-NameToSid | Should match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+'
    }
}


Describe "Convert-SidToName" {
    It "Should convert local sid to name" {
        Convert-SidToName -SID 'S-1-5-21-2620891829-2411261497-1773853088-502' | Should be 'DEV\krbtgt'
    }
    It "Should convert remote sid to name" {
        Convert-SidToName -SID 'S-1-5-21-456218688-4216621462-1491369290-502' | Should be 'TESTLAB\krbtgt'
    }
    It "Should convert built-in SIDs" {
        Convert-SidToName -SID 'S-1-5-32-556' | Should be 'BUILTIN\Network Configuration Operators'
    }
    It "Should accept pipeline input" {
        'S-1-5-9' | Convert-SidToName | Should be 'Enterprise Domain Controllers'
    }
}


Describe "Convert-NT4toCanonical" {
    It "Should convert local NT4 name to canonical" {
        Convert-NT4toCanonical -ObjectName 'DEV\krbtgt' | Should be 'dev.testlab.local/Users/krbtgt'
    }
    It "Should convert remote NT4 name to canonical" {
        Convert-NT4toCanonical -ObjectName 'TESTLAB\krbtgt' | Should be 'testlab.local/Users/krbtgt'
    }
    It "Should accept pipeline input" {
        'TESTLAB\krbtgt' | Convert-NT4toCanonical | Should be 'testlab.local/Users/krbtgt'
    }
}


Describe "Get-Proxy" {
    # TODO: implement more proxy testing
    It "Should not throw" {
        {Get-Proxy} | Should Not Throw
    }
}


Describe "Get-NameField" {
    It "Should extract dnshostname field from custom object" {
        $Object = New-Object -TypeName PSObject -Property @{'dnshostname' = 'testing1'}
        if ( (Get-NameField -Object $Object).dnshostname -ne 'testing1') {
            Throw "'dnshostname' field not parsed correctly"
        }
    }
    It "Should extract name field from custom object" {
        $Object = New-Object -TypeName PSObject -Property @{'name' = 'testing2'}
        if ( (Get-NameField -Object $Object).name -ne 'testing2') {
            Throw "'name' field not parsed correctly"
        }
    } 
    It "Should handle plaintext strings" {
        if ( (Get-NameField -Object 'testing3') -ne 'testing3') {
            Throw "Plaintext string not parsed correctly"
        }
    } 
    It "Should accept pipeline input" {
        $Object = New-Object -TypeName PSObject -Property @{'dnshostname' = 'testing4'}
        if ( ($Object | Get-NameField).dnshostname -ne 'testing4') {
            Throw "Pipeline input not processed correctly"
        }
    }
}


Describe "Convert-LDAPProperty" {
    # TODO: figure a way to implement
}


Describe "Find-InterestingFile" {
    # TODO: implement
}


Describe "Invoke-ThreadedFunction" {
    It "Should allow threaded ping" {
        $Hosts = ,"localhost" * 100
        $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
        $Hosts = Invoke-ThreadedFunction -NoImports -ComputerName $Hosts -ScriptBlock $Ping -Threads 20
        if($Hosts.length -ne 100) {
            Throw 'Error in using Invoke-ThreadedFunction to ping localhost'
        }
    }
}


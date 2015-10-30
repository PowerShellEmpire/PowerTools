#PowerUp

PowerUp is a powershell tool to assist with local privilege escalation on 
Windows systems. It contains several methods to identify and abuse
vulnerable services, as well as DLL hijacking opportunities, vulnerable
registry settings, and escalation opportunities.

Developed by [@harmj0y](https://twitter.com/harmj0y)

Part of [PowerTools](https://github.com/PowerShellEmpire/PowerTools)


## Service Enumeration:
    Get-ServiceUnquoted             -   returns services with unquoted paths that also have a space in the name
    Get-ServiceEXEPerms             -   returns services where the current user can write to the service binary path
    Get-ServiceEXEConfig            -   returns services where the current user can modify an associated config
    Get-ServicePerms                -   returns services the current user can modify

## Service Abuse:
    Invoke-ServiceUserAdd           -   modifies a modifiable service to create a user and add it to the local administrators
    Invoke-ServiceCMD               -   execute an arbitrary command through service abuse
    Write-UserAddServiceBinary      -   writes out a patched C# service binary that adds a local administrative user
    Write-CMDServiceBinary          -   writes out a patched C# binary that executes a custom command
    Write-ServiceEXE                -   replaces a service binary with one that adds a local administrator user
    Write-ServiceEXECMD             -   replaces a service binary with one that executes a custom command
    Restore-ServiceEXE              -   restores a replaced service binary with the original executable
    Invoke-ServiceStart             -   starts a given service
    Invoke-ServiceStop              -   stops a given service
    Invoke-ServiceEnable            -   enables a given service
    Invoke-ServiceDisable           -   disables a given service
    Get-ServiceDetails              -   returns detailed information about a service

## DLL Hijacking:
    Invoke-FindDLLHijack            -   finds .dll hijacking opportunities for currently running processes
    Invoke-FindPathHijack           -   finds service %PATH% .dll hijacking opportunities
    Write-HijackDll                 -   writes out a hijackable .dll
    
## Registry Checks:
    Get-RegAlwaysInstallElevated    -   checks if the AlwaysInstallElevated registry key is set
    Get-RegAutoLogon                -   checks for Autologon credentials in the registry
    Get-VulnAutoRun                 -   checks for any modifiable binaries/scripts in HKLM autoruns
    Get-VulnAutoRunConfig           -   checks for any modifiable configs for binaries/scripts in HKLM autoruns

## Misc.:
    Get-VulnSchTask                 -   find schtasks with modifiable target files
    Get-UnattendedInstallFiles      -   finds remaining unattended installation files
    Get-Webconfig                   -   checks for any encrypted web.config strings
    Get-ApplicationHost             -   checks for encrypted application pool and virtual directory passwords
    Write-UserAddMSI                -   write out a MSI installer that prompts for a user to be added
    Invoke-AllChecks                -   runs all current escalation checks and returns a report


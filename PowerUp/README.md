#PowerUp

PowerUp is a powershell tool to assist with local privilege escalation on 
Windows systems. It contains several methods to identify and abuse
vulnerable services, as well as DLL hijacking opportunities, vulnerable
registry settings, and escalation opportunities.

Developed by [@harmj0y](https://twitter.com/harmj0y)

Part of Veil's [PowerTools](https://github.com/Veil-Framework/PowerTools)


## Service Enumeration:
    Get-ServiceUnquoted             -   returns services with unquoted paths that also have a space in the name
    Get-ServiceEXEPerms             -   returns services where the current user can write to the service binary path
    Get-ServicePerms                -   returns services the current user can modify

## Service Abuse:
    Invoke-ServiceUserAdd           -   modifies a modifiable service to create a user and add it to the local administrators
    Write-UserAddServiceBinary      -   writes out a patched C# service binary that adds a local administrative user
    Write-CMDServiceBinary          -   writes out a patched C# binary that executes a custom command
    Write-ServiceEXE                -   replaces a service binary with one that adds a local administrator user
    Write-ServiceEXECMD             -   replaces a service binary with one that executes a custom command
    Restore-ServiceEXE              -   restores a replaced service binary with the original executable

## DLL Hijacking:
    Invoke-FindDLLHijack            -   finds DLL hijacking opportunities for currently running processes
    Invoke-FindPathHijack           -   finds service %PATH% .DLL hijacking opportunities

## Registry Checks:
    Get-RegAlwaysInstallElevated    -   checks if the AlwaysInstallElevated registry key is set
    Get-RegAutoLogon                -   checks for Autologon credentials in the registry

## Misc. Checks:
    Get-UnattendedInstallFiles      -   finds remaining unattended installation files
    Get-Webconfig                   -   checks for any encrypted web.config strings
    Get-ApplicationHost             -   checks for encrypted application pool and virtual directory passwords
    Invoke-CheckLocalAdmin          -   checks if the user is effectively a local administrator

## Helpers:
    Invoke-AllChecks                -   runs all current escalation checks and returns a report
    Write-UserAddMSI                -   write out a MSI installer that prompts for a user to be added
    Invoke-ServiceStart             -   starts a given service
    Invoke-ServiceStop              -   stops a given service
    Invoke-ServiceEnable            -   enables a given service
    Invoke-ServiceDisable           -   disables a given service
    Get-ServiceDetails              -   returns detailed information about a service

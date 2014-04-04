#Veil-PowerView

Veil-PowerView is a powershell tool to gain network situational awareness on 
Windows domains. It contains a set of pure-powershell replacements for various 
windows "net *" commands, which utilize powershell AD hooks and underlying 
Win32 API functions to perform useful Windows domain functionality.

It also impements various useful metafunctions, including a port 
of [Rob Fuller's](https://twitter.com/mubix) [netview.exe](https://github.com/mubix/netview) tool,
and some custom-written 'UserHunter' functions which will identify where on the
network specific users are logged into. It can also check which machines
on the domain the current user has local administrator access on. See function
descriptions for appropriate usage and available options.


Veil-PowerView is a part of the [Veil-Framework](https://www.veil-framework.com/) 
and was developed by [@harmj0y](https://twitter.com/harmj0y).


Thanks to:
    [@davidpmcguire](https://twitter.com/davidpmcguire) for inspiration, 
    [@mubix](https://twitter.com/mubix) for building netview.exe and open sourcing it,
    [@obscuresec](https://twitter.com/obscuresec), [@mattifestation](https://twitter.com/mattifestation) and [darkoperator](https://twitter.com/Carlos_Perez) for examples and how to write proper powershell modules,
    zeknox, smilingraccoon, and r3dy for the [local_admin_search_enum](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb) idea in Metasploit,
    dunedinite, normanj, and powershellmagazine.com, for some (cited) examples to adapt and draw from


## net * Functions:
    Resolve-IP                      -   resolves a hostname to an IP
    Test-Server                     -   tests connectivity to a specified server
    Get-NetDomain                   -   gets the name of the current user's domain
    Get-NetDomainController         -   gets the domain controller of the current computer's domain
    Get-NetCurrentUser              -   gets the current [domain\\]username
    Get-NetUsers                    -   gets a list of all current users in the domain
    Get-NetUsersAPI                 -   gets a list of all current users in the domain using NetUserEnum
    Get-NetUser                     -   gets data for a specified domain user
    Invoke-NetUserAdd               -   adds a local or domain user
    Get-NetGroups                   -   gets a list of all current groups in the domain
    Get-NetGroup                    -   gets a list of all current users in a specified domain group
    Get-NetGroupUsers               -   gets data for each user in a specified group
    Invoke-NetGroupUserAdd          -   adds a user to a specified local or domain group
    Get-NetComputers                -   gets a list of all current servers in the domain
    Get-NetServersAPI               -   gets a list of all current servers in the domain using the Windows API
    Get-NetServerGetInfo            -   gets information on a specified server on the domain
    Get-NetFileServers              -   get a list of file servers used by current domain users
    Get-NetShare                    -   gets share information for a specified server
    Get-NetLoggedon                 -   gets users actively logged onto a specified server
    Get-NetSessions                 -   gets active sessions on a specified server
    Get-NetConnections              -   gets active connections to a specific server resource (share)
    Get-NetFiles                    -   gets open files on a server
    Invoke-CheckLocalAdminAccess    -   check if the current user context has local administrator access
                                        to a specified host

## MetaFunctions:
    Invoke-Netview                  -   a port of @mubix's netview.exe tool using Get-Net* functionality
                                        finds all machines on the local domain and runs various enumeration
                                        methods on what it finds
    Invoke-UserHunter               -   finds machines on the local domain where specified users are logged into,
                                        and can optionsally check if the current user has local admin access
                                        to found machines
    Invoke-StealthUserHunter        -   finds all file servers utilizes in user HomeDirectories, and checks 
                                        the sessions one each file server, hunting for particular users
    Invoke-ShareFinder              -   finds non-standard shares on hosts in the local domain
    Invoke-FindLocalAdminAccess     -   finds machines on the domain that the current user has local admin access to
    Invoke-UserDescSearch           -   searches user descriptions for particular terms
    Invoke-FindVulnSystems          -   finds systems likely vulnerable to MS08-067

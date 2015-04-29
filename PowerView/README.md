#PowerView

PowerView is a PowerShell tool to gain network situational awareness on 
Windows domains. It contains a set of pure-PowerShell replacements for various 
windows "net *" commands, which utilize PowerShell AD hooks and underlying 
Win32 API functions to perform useful Windows domain functionality.

It also impements various useful metafunctions, including a port 
of [Rob Fuller's](https://twitter.com/mubix) [netview.exe](https://github.com/mubix/netview) tool,
and some custom-written 'UserHunter' functions which will identify where on the
network specific users are logged into. It can also check which machines
on the domain the current user has local administrator access on. See function
descriptions for appropriate usage and available options.

To run on a machine, start PowerShell with "powershell -exec bypass" and then load
the PowerView module with: PS> Import-Module .\powerview.psm1
    or load the PowerView script by itself: PS> Import-Module .\powerview.ps1

For detailed output of underlying functionality, pass the -Debug flag to most functions.

For functions that enumerate multiple machines, pass the -Verbose flag to get a
progress status as each host is enumerated. Most of the "meta" functions accept 
an array of hosts from the pipeline.

Developed by [@harmj0y](https://twitter.com/harmj0y)

Part of Veil's [PowerTools](https://github.com/Veil-Framework/PowerTools)

Thanks to:
    [@davidpmcguire](https://twitter.com/davidpmcguire) for inspiration, 
    [@mubix](https://twitter.com/mubix) for building netview.exe and open sourcing it,
    [@obscuresec](https://twitter.com/obscuresec), [@mattifestation](https://twitter.com/mattifestation) and [darkoperator](https://twitter.com/Carlos_Perez) for examples and how to write proper PowerShell modules,
    zeknox, smilingraccoon, and r3dy for the [local_admin_search_enum](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb) idea in Metasploit,
    dunedinite, normanj, and powershellmagazine.com, for some (cited) examples to adapt and draw from


## Misc Functions:
    Get-HostIP                      -   resolves a hostname to an IP
    Check-Write                     -   checks if the current user can write to the specified file
    Set-MacAttribute                -   Sets MAC attributes for a file based on another file or input (from Powersploit)
    Invoke-CopyFile                 -   copies a local file to a remote location, matching MAC properties
    Test-Server                     -   tests connectivity to a specified server
    Get-UserProperties              -   returns all properties specified for users, or a set of user:prop names
    Get-ComputerProperties          -   returns all properties specified for computers, or a set of computer:prop names
    Get-LastLoggedOn                -   return the last logged on user for a target host
    Get-UserLogonEvents             -   returns logon events from the event log for a specified host
    Get-UserTGTEvents               -   returns TGT request events for a specified host
    Invoke-CheckLocalAdminAccess    -   check if the current user context has local administrator access
                                        to a specified host
    Invoke-SearchFiles              -   search a local or remote path for files with specific terms in the name
    Convert-NameToSid               -   converts a user/group name to a security identifier (SID)
    Convert-SidToName               -   converts a security identifier (SID) to a group/user name


## net * Functions:
    Get-NetDomain                   -   gets the name of the current user's domain
    Get-NetForest                   -   gets the forest associated with the current user's domain
    Get-NetForestDomains            -   gets all domains for the current forest
    Get-NetDomainControllers        -   gets the domain controllers for the current computer's domain
    Get-NetCurrentUser              -   gets the current [domain\\]username
    Get-NetUser                     -   returns all user objects, or the user specified (wildcard specifiable)
    Get-NetUserSPNs                 -   gets all user ServicePrincipalNames
    Get-NetOUs                      -   gets data for domain organization units
    Get-NetGUIDOUs                  -   finds domain OUs linked to a specific GUID
    Invoke-NetUserAdd               -   adds a local or domain user
    Get-NetGroups                   -   gets a list of all current groups in the domain
    Get-NetGroup                    -   gets data for each user in a specified domain group
    Get-NetLocalGroups              -   gets a list of localgroups on a remote host or hosts
    Get-NetLocalGroup               -   gets the members of a localgroup on a remote host or hosts
    Get-NetLocalServices            -   gets a list of running services/paths on a remote host or hosts
    Invoke-NetGroupUserAdd          -   adds a user to a specified local or domain group
    Get-NetComputers                -   gets a list of all current servers in the domain
    Get-NetFileServers              -   get a list of file servers used by current domain users
    Get-NetShare                    -   gets share information for a specified server
    Get-NetLoggedon                 -   gets users actively logged onto a specified server
    Get-NetSessions                 -   gets active sessions on a specified server
    Get-NetFileSessions             -   returned combined Get-NetSessions and Get-NetFiles
    Get-NetConnections              -   gets active connections to a specific server resource (share)
    Get-NetFiles                    -   gets open files on a server
    Get-NetProcesses                -   gets the remote processes and owners on a remote server


## User-Hunting Functions:
    Invoke-UserHunter               -   finds machines on the local domain where specified users are
                                        logged into, and can optionally check if the current user has 
                                        local admin access to found machines
    Invoke-UserHunterThreaded       -   threaded version of Invoke-UserHunter
    Invoke-StealthUserHunter        -   finds all file servers utilizes in user HomeDirectories, and checks 
                                        the sessions one each file server, hunting for particular users
    Invoke-UserProcessHunter        -   hunts for processes on domain machines running under specific
                                        target user accounts
    Invoke-ProcessHunter            -   hunts for processes with a specific name on domain machines
    Invoke-UserEventHunter          -   hunts for user logon events in domain controller event logs


## Domain Trust Functions:
    Get-NetDomainTrusts             -   gets all trusts for the current user's domain
    Get-NetDomainTrustsLDAP         -   gets all trusts for the current user's domain using just LDAP 
                                        queries. This is less accurate than Get-NetDomainTrusts but
                                        allows you to relay all traffic through your primary DC.
    Get-NetForestTrusts             -   gets all trusts for the forest associated with the current user's domain
    Invoke-FindUserTrustGroups      -   enumerates users who are in groups outside of their principal domain
    Invoke-FindAllUserTrustGroups   -   map all domain trusts and enumerate all users who are in groups outside 
                                        of their principal domain
    Invoke-MapDomainTrusts          -   try to build a relational mapping of all domain trusts
    Invoke-MapDomainTrustsLDAP      -   try to build a relational mapping of all domain trusts using
                                        Get-NetDomainTrustsLDAP


## MetaFunctions:
    Invoke-Netview                  -   a port of @mubix's netview.exe tool using Get-Net* functionality
                                        finds all machines on the local domain and runs various enumeration
                                        methods on what it finds
    Invoke-NetviewThreaded          -   threaded version of Invoke-NetView
    Invoke-UserView                 -   returns parsable session/loggedon user data for a given domain
    Invoke-ShareFinder              -   finds (non-standard) shares on hosts in the local domain
    Invoke-ShareFinderThreaded      -   threaded version if Invoke-ShareFinder
    Invoke-FileFinder               -   finds potentially sensitive files on hosts in the local domain
    Invoke-FileFinderThreaded       -   threaded version of Invoke-FileFinder
    Invoke-FindLocalAdminAccess     -   finds machines on the domain that the current user has local admin 
                                        access to
    Invoke-FindLocalAdminAccesThreaded- threaded version of Invoke-FindLocalAdminAccess
    Invoke-UserFieldSearch          -   searches a user field for a particular term
    Invoke-ComputerFieldSearch      -   searches a computer field for a particular term
    Get-ExploitableSystems          -   finds systems likely vulnerable to common exploits
    Invoke-HostEnum                 -   run all available enumeration checks on a single host
    Invoke-EnumerateLocalAdmins     -   enumerates members of the local Administrators groups across all
                                        machines in the domain
    Invoke-EnumerateLocalAdminsThreaded-threaded version of Invoke-EnumerateLocalAdmins

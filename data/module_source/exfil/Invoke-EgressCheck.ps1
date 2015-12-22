<#

This module aims to offer the ability to generate arbitrary traffic on the ports specified, using the protocol specified.
Author: Stuart Morgan (@ukstufus)
Web: https://github.com/stufus

#>

function Invoke-EgressCheck {

  <#
  .SYNOPSIS

  Generates arbitrary traffic on the ports specified, using the protocol specified.

  .DESCRIPTION

  This will attempt to asynchronously generate a connection on each port specified, using the 
  protocol specified, to a target. This is most useful when attempting to identify breaches 
  in a firewall from an egress perspective. Note that it is quite noisy, but it may be 
  appropriate in some situations.

  A listener on the destination IP address will be required. The EgressChecker tool could
  be useful for this (accessible at https://github.com/stufus/egresscheck-framework) or any
  other method of identifying incoming connections will be fine.

  .PARAMETER ip

  The IP address of the target endpoint.
  Example: -ip "10.0.0.1"

  .PARAMETER portrange

  The ports to try. This accepts comma-separated individual port numbers, ranges
  or both.
  Example: -portrange "22-25,53,80,443,445,3306,3389"
  Default: "22-25,53,80,443,445,3306,3389"

  .PARAMETER protocol

  The IP protocol to use. This can be one of TCP, UDP or ALL.
  Example: -protocol "TCP"
  Default: TCP

  .PARAMETER verbose

  The verbosity of the console output.
  If this is unset, there is no intentional verbosity.
  If this is set, it will output:
    't/port' - Sending a TCP packet
    'u/port' - Sending a UDP packet
    'W/tcp' - Waiting (i.e. sleep/delay) after a TCP connection was attempted
    'W/udp' - Waiting (i.e. sleep/delay) after a UDP connection was attempted
  Example: -verbose
  Default: Not verbose

  .PARAMETER delay

  The delay between sending packets. This injects a delay in milliseconds between
  packets generated on a per-port per-protocol basis. 
  Example: -delay 100
  Default: 100

  .EXAMPLE
  Invoke-EgressCheck -ip 1.2.3.4 -portrange "22-25,53,80,443,445,3306,3389" -protocol ALL -delay 100 -verbose

  .LINK

    https://github.com/stufus/egresscheck-framework

  #>

  [CmdletBinding()]
  param([string] $ip, [string] $portrange = "22-25,53,80,443,445,3306,3389", [string] $protocol = "TCP", [int] $delay=100)

    if ($ip -NotMatch '^([0-9]{1,3}\.){3}[0-9]{1,3}$') {
        Write-Error "IP not specified"
        return
    }

    Write-Output "EgressCheck started"

    $pr_split = $portrange -split ','
    foreach ($p in $pr_split) {
        if ($p -match '^[0-9]+-[0-9]+$') {
            $prange = $p -split '-'
            $s = [convert]::ToInt32($prange[0])
            $e = [convert]::ToInt32($prange[1])
            Write-Verbose "Now generating traffic on ports $s - $e"
            for ($c = $s;$c -le $e;$c++) {
                egress -ip $ip -port $c -delay $delay -protocol $protocol
            }
        } elseif ($p -match '^[0-9]+$') {
            $c = [convert]::ToInt32($p)
            Write-Verbose "Now generating traffic on port $c"
            egress -ip $ip -port $c -delay $delay -protocol $protocol
        } else {
            Write-Error "Bad port range"
            return
        }
    }
    Write-Output "EgressCheck completed"
}

function egress {
    [CmdletBinding()]
    param([string]$ip, [int]$port, [int]$delay, [string]$protocol) 

    $protocol_case = $protocol.ToUpper()

    if ($protocol_case -eq "TCP" -Or $protocol_case -eq "ALL") {
	    generate_tcp -ip $ip -port $port
        if ($delay -gt 0) {
            Start-Sleep -m ($delay)
            Write-Verbose "W/tcp"
        }
     }

    if ($protocol_case -eq "UDP" -Or $protocol_case -eq "ALL") {
	    generate_udp -ip $ip -port $port
        if ($delay -gt 0) {
            Start-Sleep -m ($delay)
            Write-Verbose "W/udp"
        }
    }

}

# Send the TCP packet
function generate_tcp {
    [CmdletBinding()]
    param([string]$ip, [int]$port)

	try {
		$t = New-Object System.Net.Sockets.TCPClient
		$t.BeginConnect($ip, $port, $null, $null) | Out-Null
        $t.Close()
        Write-Verbose "t/$port"
	}
	catch { }
}

# Send the UDP packet
function generate_udp {
    [CmdletBinding()]
    param([string]$ip, [int]$port)

    $d = [system.Text.Encoding]::UTF8.GetBytes(".")
	try {
		$t = New-Object System.Net.Sockets.UDPClient
        $t.Send($d, $d.Length, $ip, $port) | Out-Null
        $t.Close()
        Write-Verbose "u/$port"
	}
	catch { }
}

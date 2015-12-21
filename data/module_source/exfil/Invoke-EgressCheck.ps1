<#

This module aims to offer the ability to generate 
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
    't' - Sending a TCP packet
    'u' - Sending a UDP packet
    'W' - Waiting (i.e. sleep/delay)
  Example: -verbose
  Default: Not set

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

    $pr_split = $portrange -split ','
    $verbosity = 0
    if $verbose { $verbosity = 1 }
    foreach ($p in $pr_split) {
        if ($p -match '^[0-9]+-[0-9]+$') {
            $prange = $p -split '-'
            for ($c = [convert]::ToInt32($prange[0]);$c -le [convert]::ToInt32($prange[1]);$c++) {
                egress -ip $ip -port $c -verbosity $verbosity -delay $delay -protocol $protocol
            }
        } elseif ($p -match '^[0-9]+$') {
            egress -ip $ip -port $c -verbosity $verbosity -delay $delay -protocol $protocol
        } else {
            Write-Error "Bad port range"
            return
        }
    }
    Write-Verbose ""

}

function egress {
    [CmdletBinding()]
    param([string]$ip, [int]$port, [int]$verbosity, [int]$delay, [string]$protocol) 

    if ($protocol -eq "TCP" -Or $protocol -eq "ALL") {
	    generate_tcp -ip $ip -port $port -verbosity $verbosity
        if ($delay -gt 0) {
            Start-Sleep -m ($delay)
            if ($verbosity -gt 0) { Write-Verbose -NoNewLine "W" }
        }
     }

    if ($protocol -eq "UDP" -Or $protocol -eq "ALL") {
	    generate_udp -ip $ip -port $port -verbosity $verbosity
        if ($delay -gt 0) {
            Start-Sleep -m ($delay)
            if ($verbosity -gt 0) { Write-Verbose -NoNewLine "W" }
        }
    }

}

# Send the TCP packet
function generate_tcp {
    [CmdletBinding()]
    param([string]$ip, [int]$port, [int]$verbosity)

	try {
		$t = New-Object System.Net.Sockets.TCPClient
		$t.BeginConnect($ip, $port, $null, $null) | Out-Null
        $t.Close()
        if ($verbosity -gt 0) { Write-Verbose -NoNewLine "t" }
	}
	catch { }
}

# Send the UDP packet
function generate_udp {
    [CmdletBinding()]
    param([string]$ip, [int]$port,[int]$verbosity)

    $d = [system.Text.Encoding]::UTF8.GetBytes(".")
	try {
		$t = New-Object System.Net.Sockets.UDPClient
        $t.Send($d, $d.Length, $ip, $port) | Out-Null
        $t.Close()
        if ($verbosity -gt 0) { Write-Verbose -NoNewLine "u" }
	}
	catch { }
}

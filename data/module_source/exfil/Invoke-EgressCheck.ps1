function Invoke-EgressCheck {
  <#
  .SYNOPSIS

  Generates traffic on the ports specified, using the protocol specified.
  This is most useful when attempting to identify breaches in a firewall from
  an egress perspective.

  A listener on the destination IP address will be required.

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
  If this is 0, there is no intentional verbosity.
  If this is 1, it will output:
    't' - Sending a TCP packet
    'u' - Sending a UDP packet
    'W' - Waiting (i.e. sleep/delay)

  Example: -verbose 0
  Default: 0

  #>

  [CmdletBinding()]
  param([string] $ip, [string] $portrange = "22-25,53,80,443,445,3306,3389", [string] $protocol = "TCP", [int] $verbose=0)

    $pr_split = $portrange -split ','
    $ports = @()
    foreach ($p in $pr_split) {
        if ($p -match '^[0-9]+-[0-9]+$') {
            $prange = $p -split '-'
            for ($c = [convert]::ToInt32($prange[0]);$c -le [convert]::ToInt32($prange[1]);$c++) {
                $ports += $c
            }
        } elseif ($p -match '^[0-9]+$') {
            $ports += $p
        } else {
            return
        }
    }

    foreach ($eachport in $ports) {
		generate_tcp -ip $ip -port $eachport -verbose $verbose
		generate_udp -ip $ip -port $eachport -verbose $verbose
        Start-Sleep -m (0.2*1000)
    }

}

# Send the TCP packet async
function generate_tcp {
    [CmdletBinding()]
    param([string]$ip, [int]$port, [int]$verbose)

	try {
		$t = New-Object System.Net.Sockets.TCPClient
		$t.BeginConnect($ip, $port, $null, $null) | Out-Null
        $t.Close()
        if ($verbose>0) { Write-Host -NoNewLine "t" }
	}
	catch { }
}

# Send the UDP packet async
function generate_udp {
    [CmdletBinding()]
    param([string]$ip, [int]$port,[int]$verbose)

    $d = [system.Text.Encoding]::UTF8.GetBytes(".")
	try {
		$t = New-Object System.Net.Sockets.UDPClient
        $t.Send($d, $d.Length, $ip, $port) | Out-Null
        $t.Close()
        if ($verbose>0) { Write-Host -NoNewLine "u" }
	}
	catch { }
}

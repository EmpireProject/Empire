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

  Example: -portrange "22,23,53,500-1000,1024,1025-1100"

  #>

  [CmdletBinding()]
  param([string] $ip, [string] $portrange, [string] $protocol) 

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
        Write-Output "Sending TCP/$eachport to $ip"
		_tcp -ip $ip -port $eachport
        Write-Output "Sending UDP/$eachport to $ip"
		_udp -ip $ip -port $eachport
        Start-Sleep -m (0.2*1000)
    }

}

# Send the TCP packet async
function _tcp {
    [CmdletBinding()]                                                                                                                                                                           
    param([string]$ip, [int]$port)

	try {                                                                                                                                                                                       
		$t = New-Object System.Net.Sockets.TCPClient                                                                                                                              
		$t.BeginConnect($ip, $port, $null, $null) | Out-Null
        $t.Close()
        
	}
	catch { }  
}

# Send the UDP packet async
function _udp {
    [CmdletBinding()]                                                                                                                                                                           
    param([string]$ip, [int]$port)

    $d = [system.Text.Encoding]::UTF8.GetBytes(".")
	try {                                                                                                                                                                                       
		$t = New-Object System.Net.Sockets.UDPClient       
        $t.Send($d, $d.Length, $ip, $port) | Out-Null
        $t.Close()        
	}
	catch { }  
}

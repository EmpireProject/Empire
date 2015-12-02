# Perform the egress check
function ec {
    [CmdletBinding()]                                                                                                                                                                           
    param([string]$ip, [string]$pr) 

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
            #Error in port definition
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

# Set the parameters
ec -ip "192.0.2.1" -pr "20-30,40,50"
function Start-TCPMonitor {
    [cmdletbinding()]
    Param(          
        [Parameter(Mandatory=$true)]  
        [String]$TargetDomain,
        [Parameter(Mandatory=$false)]
        [Int]$CheckInterval=30
    )

    Function Get-ActiveTCPConnections {                                          
        try {            
            $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
            $Connections = $TCPProperties.GetActiveTcpConnections() 
            return $Connections                     
                    
        } catch {            
            Write-Error "Failed to get active connections. $_"  
            return @()           
        }           
    }

    While(1){
        $TargetDomainResolution = [System.Net.Dns]::GetHostAddresses("$TargetDomain")
        $TargetIPs = New-Object System.Collections.ArrayList
        foreach($i in $TargetDomainResolution ) { 
            $TargetIPs.Add($i.IPAddressToString.trim()) >$null 2>&1
        }
        $tcpConns = Get-ActiveTCPConnections
        foreach($Connection in $tcpConns) {
            foreach($IP in $TargetIPs) {
                if( $Connection.RemoteEndPoint.Address.IPAddressToString -eq $IP ) {
                    "Host connected to $TargetDomain"
                }
           }
        }

        sleep($CheckInterval)
     
   }
}

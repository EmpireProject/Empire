function Invoke-TCPMonitor {
    [cmdletbinding()]
    Param(          
        [Parameter(Mandatory=$true)]  
        [String]$TargetDomain
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

    While($True){
        $TargetIP = [System.Net.Dns]::GetHostAddresses("$TargetDomain")[0].IPAddressToString.trim()
        $tcpConns = Get-ActiveTCPConnections
        foreach($Connection in $tcpConns){
           if( $Connection.RemoteEndPoint.Address.IPAddressToString -eq $TargetIP ) {
                Write-Output "Host connected to $TargetDomain"
           }
        }
        sleep(30)
     
   }
}

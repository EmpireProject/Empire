function Send-mDNSCommand {
    <#
    .SYNOPSIS
    Send a command via multicast
    .DESCRIPTION
    Send a command via multicast
    .EXAMPLE
    Send-mDNSCommand -Command "Get-Process"
    .PARAMETER MultiCastGroup
    The Multicast Group to listen on
    .PARAMETER MultiCastPort
    The port to listen for UDP packets
    .PARAMETER BindPort
    The port to bind to for sending UDP packets
    .PARAMETER Command
    The command to run
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [String]
        $MultiCastGroup = "224.1.1.1",

        [Parameter(Mandatory = $false, Position = 1)]
        [String]
        $MultiCastPort = 51111,

        [Parameter(Mandatory = $false, Position = 1)]
        [String]
        $BindPort = 51112,
        
        [Parameter(Mandatory = $false, Position = 0)]
        [String]
        $Command = "Get-Process"
    )
    Begin {
        $udp_client = new-Object System.Net.Sockets.UdpClient $BindPort
        $multicast_group = [IPAddress]$MultiCastGroup
        $udp_client.JoinMulticastGroup($multicast_group)
        $enc = [system.Text.Encoding]::UTF8
        $response_packet = $enc.GetBytes($Command) 
        $endpoint = New-Object Net.IPEndpoint([IPAddress]$MultiCastGroup,$MultiCastPort)
    }
    Process {
        Try {
            $udp_client.Connect($endpoint)
            $udp_client.Send($response_packet,$response_packet.Length) |Out-Null  
            $udp_client.Close()
            $udp_client = New-Object System.Net.Sockets.UdpClient
            $udp_client.ExclusiveAddressUse = $False
            $LocalEndPoint = New-Object System.Net.IPEndPoint([ipaddress]::Any,$MultiCastPort)
            $udp_client.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress,$true)
            $udp_client.ExclusiveAddressUse = $False
            $udp_client.Client.Bind($LocalEndPoint)
            $multicast_group = [IPAddress]::Parse($MultiCastGroup)
            $udp_client.JoinMulticastGroup($multicast_group)
            While ($true) {
                $receivebytes = $udp_client.Receive([ref]$endpoint)
                ([text.encoding]::ASCII).GetString($receivebytes)
                $udp_client.Close()|Out-Null
                break
                
            } 
        }                
        Catch {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
        }
    }
    End {
        $udp_client.Close()
    }
}

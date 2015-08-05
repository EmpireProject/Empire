
function Test-Server {
    <#
        .SYNOPSIS
        Tests a connection to a remote server.

        .DESCRIPTION
        This function uses either ping (test-connection) or RPC
        (through WMI) to test connectivity to a remote server.

        .PARAMETER Server
        The hostname/IP to test connectivity to.

        .OUTPUTS
        $True/$False

        .EXAMPLE
        > Test-Server -Server WINDOWS7
        Tests ping connectivity to the WINDOWS7 server.

        .EXAMPLE
        > Test-Server -RPC -Server WINDOWS7
        Tests RPC connectivity to the WINDOWS7 server.

        .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Enhanced-Remote-Server-84c63560
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [String]
        $Server,

        [Switch]
        $RPC
    )

    process {
        if ($RPC){
            $WMIParameters = @{
                            namespace = 'root\cimv2'
                            Class = 'win32_ComputerSystem'
                            ComputerName = $Name
                            ErrorAction = 'Stop'
                          }
            if ($Credential -ne $null)
            {
                $WMIParameters.Credential = $Credential
            }
            try
            {
                Get-WmiObject @WMIParameters
            }
            catch {
                Write-Verbose -Message 'Could not connect via WMI'
            }
        }
        # otherwise, use ping
        else{
            Test-Connection -ComputerName $Server -count 1 -Quiet
        }
    }
}


function Get-NetDomainController {
    <#
        .SYNOPSIS
        Return the current domain controllers for the active domain.

        .PARAMETER Domain
        The domain to query for domain controllers. If not supplied, the
        current domain is used.

        .EXAMPLE
        > Get-NetDomainController
        Returns the domain controllers for the current computer's domain.
        Approximately equivialent to the hostname given in the LOGONSERVER
        environment variable.

        .EXAMPLE
        > Get-NetDomainController -Domain test
        Returns the domain controllers for the domain "test".
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $d = Get-NetDomain -Domain $Domain
    if($d){
        $d.DomainControllers
    }
}


function Get-NetDomain {
    <#
        .SYNOPSIS
        Returns the name of the current user's domain.

        .PARAMETER Domain
        The domain to query return. If not supplied, the
        current domain is used.

        .EXAMPLE
        > Get-NetDomain
        Return the current domain.

        .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>

    [CmdletBinding()]
    param(
        [String]
        $Domain
    )

    if($Domain -and ($Domain -ne "")){
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else{
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}



function Get-NetComputer {
    <#
        .SYNOPSIS
        Gets an array of all current computers objects in a domain.

        .DESCRIPTION
        This function utilizes adsisearcher to query the current AD context
        for current computer objects. Based off of Carlos Perez's Audit.psm1
        script in Posh-SecMod (link below).

        .PARAMETER HostName
        Return computers with a specific name, wildcards accepted.

        .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.

        .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.

        .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER FullData
        Return full user computer objects instead of just system names (the default).

        .PARAMETER Domain
        The domain to query for computers.

        .OUTPUTS
        System.Array. An array of found system objects.

        .EXAMPLE
        > Get-NetComputer
        Returns the current computers in current domain.

        .EXAMPLE
        > Get-NetComputer -SPN mssql*
        Returns all MS SQL servers on the domain.

        .EXAMPLE
        > Get-NetComputer -Domain testing
        Returns the current computers in 'testing' domain.

        > Get-NetComputer -Domain testing -FullData
        Returns full computer objects in the 'testing' domain.

        .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = '*',

        [string]
        $SPN = '*',

        [string]
        $OperatingSystem = '*',

        [string]
        $ServicePack = '*',

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [string]
        $Domain
    )

    process {
        # if a domain is specified, try to grab that domain
        if ($Domain){

            # try to grab the primary DC for the current domain
            try{
                $PrimaryDC = ([Array](Get-NetDomainController))[0].Name
            }
            catch{
                $PrimaryDC = $Null
            }

            try {
                # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
                $dn = "DC=$($Domain.Replace('.', ',DC='))"

                # if we could grab the primary DC for the current domain, use that for the query
                if($PrimaryDC){
                    $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
                }
                else{
                    # otherwise try to connect to the DC for the target domain
                    $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                }

                # create the searcher object with our specific filters
                if ($ServicePack -ne '*'){
                    $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
                }
                else{
                    # server 2012 peculiarity- remove any mention to service pack
                    $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
                }

            }
            catch{
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            }
        }
        else{
            # otherwise, use the current domain
            if ($ServicePack -ne '*'){
                $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
            }
            else{
                # server 2012 peculiarity- remove any mention to service pack
                $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
            }
        }

        if ($CompSearcher){

            # eliminate that pesky 1000 system limit
            $CompSearcher.PageSize = 200

            $CompSearcher.FindAll() | ? {$_} | ForEach-Object {
                $up = $true
                if($Ping){
                    $up = Test-Server -Server $_.properties.dnshostname
                }
                if($up){
                    # return full data objects
                    if ($FullData){
                        $properties = $_.Properties
                        $out = New-Object psobject

                        $properties.PropertyNames | % {
                            if ($_ -eq "objectsid"){
                                # convert the SID to a string
                                $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                            }
                            elseif($_ -eq "objectguid"){
                                # convert the GUID to a string
                                $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                            }
                            elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") ){
                                $out | Add-Member Noteproperty $_ ([datetime]::FromFileTime(($properties[$_][0])))
                            }
                            else {
                                $out | Add-Member Noteproperty $_ $properties[$_][0]
                            }
                        }
                        $out | Out-String
                    }
                    else{
                        # otherwise we're just returning the DNS host name
                        $_.properties.dnshostname + "`n"
                    }
                }
            }
        }

    }
}

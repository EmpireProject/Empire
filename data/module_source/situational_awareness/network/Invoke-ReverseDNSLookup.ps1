
function Invoke-ReverseDNSLookup
{
    <#
    .Synopsis
       Performs a DNS Reverse Lookup of a given IPv4 IP Range.
       Part of Posh-SecMod (https://github.com/darkoperator/Posh-SecMod/)
       Author: darkoperator
    .DESCRIPTION
       Performs a DNS Reverse Lookup of a given IPv4 IP Range.
    .EXAMPLE
       Perfrom a threaded reverse lookup against a given CIDR
       PS C:\> Invoke-ReverseDNSLookup -CIDR 192.168.1.0/24
    .EXAMPLE
       Perfrom a reverse lookup against a given range given the start and end IP Addresses
       PS C:\> Invoke-ReverseDNSLookup -Range 192.168.1.1-192.168.1.20
    .LINK
       https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ParameterSetName = "Range",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Range,

        [Parameter(Mandatory=$true,
                   ParameterSetName = "CIDR",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$CIDR,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$MaxThreads=30,
        [Parameter(
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int]$TimeOut = 200
    )

    Begin
    {
        function New-IPv4Range
        {
            <#
            .Synopsis
                Generates a list of IPv4 IP Addresses given a Start and End IP.
            .DESCRIPTION
                Generates a list of IPv4 IP Addresses given a Start and End IP.
            #>
            param(
                [Parameter(Mandatory=$true,
                           ValueFromPipelineByPropertyName=$true,
                           Position=0)]
                           $StartIP,
                           
                [Parameter(Mandatory=$true,
                           ValueFromPipelineByPropertyName=$true,
                           Position=2)]
                           $EndIP          
            )
            
            # created by Dr. Tobias Weltner, MVP PowerShell
            $ip1 = ([System.Net.IPAddress]$StartIP).GetAddressBytes()
            [Array]::Reverse($ip1)
            $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

            $ip2 = ([System.Net.IPAddress]$EndIP).GetAddressBytes()
            [Array]::Reverse($ip2)
            $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

            for ($x=$ip1; $x -le $ip2; $x++) {
                $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
                [Array]::Reverse($ip)
                $ip -join '.'
            }
        }


        function New-IPv4RangeFromCIDR 
        {
            <#
            .Synopsis
                Generates a list of IPv4 IP Addresses given a CIDR.
            .DESCRIPTION
                Generates a list of IPv4 IP Addresses given a CIDR.
            #>
            param(
                [Parameter(Mandatory=$true,
                           ValueFromPipelineByPropertyName=$true,
                           Position=0)]
                           $Network
            )
            # Extract the portions of the CIDR that will be needed
            $StrNetworkAddress = ($Network.split("/"))[0]
            [int]$NetworkLength = ($Network.split("/"))[1]
            $NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
            $IPLength = 32-$NetworkLength
            [Array]::Reverse($NetworkIP)
            $NumberOfIPs = ([System.Math]::Pow(2, $IPLength)) -1
            $NetworkIP = ([System.Net.IPAddress]($NetworkIP -join ".")).Address
            $StartIP = $NetworkIP +1
            $EndIP = $NetworkIP + $NumberOfIPs
            # We make sure they are of type Double before conversion
            If ($EndIP -isnot [double])
            {
                $EndIP = $EndIP -as [double]
            }
            If ($StartIP -isnot [double])
            {
                $StartIP = $StartIP -as [double]
            }
            # We turn the start IP and end IP in to strings so they can be used.
            $StartIP = ([System.Net.IPAddress]$StartIP).IPAddressToString
            $EndIP = ([System.Net.IPAddress]$EndIP).IPAddressToString
            New-IPv4Range $StartIP $EndIP
        }

        # Manage if range is given
        if ($Range)
        {
            $rangeips = $Range.Split("-")
            $targets = New-IPv4Range -StartIP $rangeips[0] -EndIP $rangeips[1]
        }

        # Manage if CIDR is given
        if ($CIDR)
        {
            $targets = New-IPv4RangeFromCIDR -Network $CIDR
        }
    }
    Process
    {
        $RvlScripBlock = {
            param($ip)
            try {
            [System.Net.Dns]::GetHostEntry($ip)
            }
            catch {}
        }

        #Multithreading setup

        # create a pool of maxThread runspaces   
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)   
        $pool.Open()
  
        $jobs = @()   
        $ps = @()   
        $wait = @()

        $i = 0

        # How many servers
        $record_count = $targets.Length

        #Loop through the endpoints starting a background job for each endpoint
        foreach ($ip in $targets)
        {
            Write-Verbose $ip
            # Show Progress
            $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
            # Write-Progress -Activity "Performing DNS Reverse Lookup Discovery" -PercentComplete $record_progress -Status "Reverse Lookup - $record_progress%" -Id 1;

            while ($($pool.GetAvailableRunspaces()) -le 0) 
            {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()

            # assign our pool of 3 runspaces to use   
            $ps[$i].runspacepool = $pool

            # command to run
            [void]$ps[$i].AddScript($RvlScripBlock).AddParameter('ip', $ip)
            #[void]$ps[$i].AddParameter('ping', $ping)
    
            # start job
            $jobs += $ps[$i].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$i].AsyncWaitHandle
    
            $i++
        }

        $waitTimeout = get-date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
  
        # end async call   
        for ($y = 0; $y -lt $i; $y++) {     
  
            try 
            {   
                # complete async job   
                $ScanResults += $ps[$y].EndInvoke($jobs[$y])   
  
            } 
            catch 
            {   
       
                # oops-ee!   
                write-warning "error: $_"  
            }
    
            finally 
            {
                $ps[$y].Dispose()
            }    
        }

        $pool.Dispose()
    }

    end
    {
        $ScanResults
    }
}

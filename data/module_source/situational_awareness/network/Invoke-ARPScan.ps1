function Invoke-ARPScan {
<#
.Synopsis
   Performs an ARP scan against a given range of IPv4 IP Addresses.
   Part of Posh-SecMod (https://github.com/darkoperator/Posh-SecMod/)
   Author: darkoperator

.DESCRIPTION
   Performs an ARP scan against a given range of IPv4 IP Addresses.
.EXAMPLE
   Invoke an ARP Scan against a range of IPs specified in CIDR Format
    PS C:\> Invoke-ARPScan -CIDR 172.20.10.1/24
    MAC                                                       Address                                                  
    ---                                                       -------                                                  
    14:10:9F:D5:1A:BF                                         172.20.10.2                                              
    00:0C:29:93:10:B5                                         172.20.10.3                                              
    00:0C:29:93:10:B5                                         172.20.10.15  

.LINK
https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1

#>
    param (
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
        [string]$MaxThreads=50
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

#https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/27/use-powershell-to-interact-with-the-windows-api-part-3/
$DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
$TypeBuilder = $ModuleBuilder.DefineType('IPHlp', 'Public, Class')

$PInvokeMethod = $TypeBuilder.DefineMethod(
    'SendARP',
    [Reflection.MethodAttributes] 'Public, Static',
    [int],
    [Type[]] @( [int], [int], [byte[]], [int].MakeByRefType() )
)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
)
$FieldValueArray = [Object[]] @(
        'SendARP',
        $True
)
$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
    $DllImportConstructor,
    @('iphlpapi.dll'),
    $FieldArray,
    $FieldValueArray
)
$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
$IPHlp = $TypeBuilder.CreateType()


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


        $scancode = {
            param($IPAddress,$IPHlp)
            $ip = [byte[]]$IPAddress.split('.')
            $mac = New-Object byte[] 6
            $lenMac = 6
            $null = $IPHlp::SendARP( [System.BitConverter]::ToInt32($ip,0), 0, $mac ,[ref] $lenMac)
            $macStr = [System.BitConverter]::ToString($mac,0,$lenMac).Replace('-',':')
            if ($macStr) {New-Object psobject -Property @{Address = $IPAddress; MAC = $macStr}}
        } # end ScanCode var

        $jobs = @()

    

        $start = get-date
        write-verbose "Begin Scanning at $start"

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
        foreach ($IPAddress in $targets)
        {
            # Show Progress
            $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
            # Write-Progress -Activity "Performing ARP Scan" -PercentComplete $record_progress -Status "Addresses Queried - $record_progress%" -Id 1;

            while ($($pool.GetAvailableRunspaces()) -le 0) 
            {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"
            $ps += [powershell]::create()

            # assign our pool of 3 runspaces to use   
            $ps[$i].runspacepool = $pool

            # command to run
            [void]$ps[$i].AddScript($scancode).AddParameter('IPaddress', $IPAddress).AddParameter('IPHlp', $IPHlp)
            #[void]$ps[$i].AddParameter()
    
            # start job
            $jobs += $ps[$i].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$i].AsyncWaitHandle
    
            $i++
        }

        write-verbose "Waiting for scanning threads to finish..."

        $waitTimeout = get-date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) 
        {
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

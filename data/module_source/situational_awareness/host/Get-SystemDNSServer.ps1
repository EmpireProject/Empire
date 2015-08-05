
function Get-SystemDNSServer
{
    <#
    .Synopsis
       Enumerates the DNS Servers used by a system
       Part of Posh-SecMod (https://github.com/darkoperator/Posh-SecMod/)
       Author: darkoperator

    .DESCRIPTION
       Enumerates the DNS Servers used by a system returning an IP Address .Net object for each.
    .EXAMPLE
       C:\> Get-SystemDNSServer
        Address            : 16885952
        AddressFamily      : InterNetwork
        ScopeId            :
        IsIPv6Multicast    : False
        IsIPv6LinkLocal    : False
        IsIPv6SiteLocal    : False
        IsIPv6Teredo       : False
        IsIPv4MappedToIPv6 : False
        IPAddressToString  : 192.168.1.1
    #>
    $DNSServerAddresses = @()
    $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    foreach($interface in $interfaces)
    {
        if($interface.OperationalStatus -eq "Up")
        {
            $DNSConfig = $interface.GetIPProperties().DnsAddresses
            if (!$DNSConfig.IsIPv6SiteLocal)
            {
                $DNSServerAddresses += $DNSConfig
            }
        }
    }
    $DNSServerAddresses
}
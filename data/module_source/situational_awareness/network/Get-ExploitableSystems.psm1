<#
	.Synopsis
	   This module will query Active Directory for the hostname, OS version, and service pack level  
	   for each computer account.  That information is then cross-referenced against a list of common
	   Metasploit exploits that can be used during penetration testing.

	.DESCRIPTION
	   This module will query Active Directory for the hostname, OS version, and service pack level  
	   for each computer account.  That information is then cross-referenced against a list of common
	   Metasploit exploits that can be used during penetration testing.  The script filters out disabled
	   domain computers and provides the computer's last logon time to help determine if it's been 
	   decommissioned.  Also, since the script uses data tables to output affected systems the results
	   can be easily piped to other commands such as test-connection or a Export-Csv.

	.EXAMPLE
	   The example below shows the standard command usage.  Disabled system are excluded by default, but
	   the "LastLgon" column can be used to determine which systems are live.  Usually, if a system hasn't 
	   logged on for two or more weeks it's been decommissioned.      

	   PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Format-Table -AutoSize
	   [*] Grabbing computer accounts from Active Directory...
	   [*] Loading exploit list for critical missing patches...
	   [*] Checking computers for vulnerable OS and SP levels...
	   [+] Found 5 potentially vulnerabile systems!

	   ComputerName          OperatingSystem         ServicePack    LastLogon            MsfModule                                      CVE                      
	   ------------          ---------------         -----------    ---------            ---------                                      ---                      
	   ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   assess-xppro.demo.com Windows XP Professional Service Pack 3 4/1/2014 11:11:54 AM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   assess-xppro.demo.com Windows XP Professional Service Pack 3 4/1/2014 11:11:54 AM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....                     

	.EXAMPLE
	   The example below shows how to write the output to a csv file.

	   PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Export-Csv c:\temp\output.csv -NoTypeInformation

	.EXAMPLE
	   The example below shows how to pipe the resultant list of computer names into the test-connection to determine if they response to ping
	   requests.

	   PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Test-Connection

	 .LINK
	   http://www.netspi.com
	   
	 .NOTES
	   Author: Scott Sutherland - 2015, NetSPI
	   Version: Get-ExploitableSystems.psm1 v1.0
	   Comments: The technique used to query LDAP was based on the "Get-AuditDSComputerAccount" 
	   function found in Carols Perez's PoshSec-Mod project.  The general idea is based off of  
	   Will Schroeder's "Invoke-FindVulnSystems" function from the PowerView toolkit.

#>
function Get-ExploitableSystems
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000.")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]
        [string]$SearchDN
    )
    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {

        # Status user
        Write-Host "[*] Grabbing computer accounts from Active Directory..."


        # ----------------------------------------------------------------
        # Setup data table for domain computer information
        # ----------------------------------------------------------------
    
        # Create data table for hostnames, os, and service packs from LDAP
        $TableAdsComputers = New-Object System.Data.DataTable 
        $TableAdsComputers.Columns.Add('Hostname') | Out-Null        
        $TableAdsComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableAdsComputers.Columns.Add('ServicePack') | Out-Null
        $TableAdsComputers.Columns.Add('LastLogon') | Out-Null


        # ----------------------------------------------------------------
        # Grab computer account information from Active Directory via LDAP
        # ----------------------------------------------------------------

        $CompFilter = "(&(objectCategory=Computer))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $CompFilter
        $ObjSearcher.SearchScope = "Subtree"

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {

            # Setup fields
            $CurrentHost = $($_.properties['dnshostname'])
            $CurrentOs = $($_.properties['operatingsystem'])
            $CurrentSp = $($_.properties['operatingsystemservicepack'])
            $CurrentLast = $($_.properties['lastlogon'])
            $CurrentUac = $($_.properties['useraccountcontrol'])

            # Convert useraccountcontrol to binary so flags can be checked
            # http://support.microsoft.com/en-us/kb/305144
            # http://blogs.technet.com/b/askpfeplat/archive/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory.aspx
            $CurrentUacBin = [convert]::ToString($CurrentUac,2)

            # Check the 2nd to last value to determine if its disabled
            $DisableOffset = $CurrentUacBin.Length - 2
            $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)

            # Add computer to list if it's enabled
            if ($CurrentDisabled  -eq 0){

                # Add domain computer to data table
                $TableAdsComputers.Rows.Add($CurrentHost,$CurrentOS,$CurrentSP,$CurrentLast) | Out-Null 
            }            
 
         }

        # Status user        
        Write-Host "[*] Loading exploit list for critical missing patches..."

        # ----------------------------------------------------------------
        # Setup data table for list of msf exploits
        # ----------------------------------------------------------------
    
        # Create data table for list of patches levels with a MSF exploit
        $TableExploits = New-Object System.Data.DataTable 
        $TableExploits.Columns.Add('OperatingSystem') | Out-Null 
        $TableExploits.Columns.Add('ServicePack') | Out-Null
        $TableExploits.Columns.Add('MsfModule') | Out-Null  
        $TableExploits.Columns.Add('CVE') | Out-Null
        
        # Add exploits to data table
        $TableExploits.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  

    

        # Status user        
        Write-Host "[*] Checking computers for vulnerable OS and SP levels..."

        # ----------------------------------------------------------------
        # Setup data table to store vulnerable systems
        # ----------------------------------------------------------------
        
        # Create data table to house vulnerable server list
        $TableVulnComputers = New-Object System.Data.DataTable 
        $TableVulnComputers.Columns.Add('ComputerName') | Out-Null
        $TableVulnComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableVulnComputers.Columns.Add('ServicePack') | Out-Null
        $TableVulnComputers.Columns.Add('LastLogon') | Out-Null
        $TableVulnComputers.Columns.Add('MsfModule') | Out-Null  
        $TableVulnComputers.Columns.Add('CVE') | Out-Null   
        
        # Iterate through each exploit
        $TableExploits | 
        ForEach-Object {
                     
            $ExploitOS = $_.OperatingSystem
            $ExploitSP = $_.ServicePack
            $ExploitMsf = $_.MsfModule
            $ExploitCve = $_.CVE

            # Iterate through each ADS computer
            $TableAdsComputers | 
            ForEach-Object {
                
                $AdsHostname = $_.Hostname
                $AdsOS = $_.OperatingSystem
                $AdsSP = $_.ServicePack                                                        
                $AdsLast = $_.LastLogon
                
                # Add exploitable systems to vul computers data table
                if ($AdsOS -like "$ExploitOS*" -and $AdsSP -like "$ExploitSP" ){                    
                   
                    # Add domain computer to data table                    
                    $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,[dateTime]::FromFileTime($AdsLast),$ExploitMsf,$ExploitCve) | Out-Null 
                }

            }

        }     
        

        # Display results
        $VulnComputer = $TableVulnComputers | select ComputerName -Unique | measure
        $vulnComputerCount = $VulnComputer.Count
        If ($VulnComputer.Count -gt 0){

            # Return vulnerable server list order with some hack date casting
            Write-Host "[+] Found $vulnComputerCount potentially vulnerabile systems!"
            $TableVulnComputers | Sort-Object { $_.lastlogon -as [datetime]} -Descending

        }else{

            Write-Host "[-] No vulnerable systems were found."

        }      

    }

    End
    {

    }
}

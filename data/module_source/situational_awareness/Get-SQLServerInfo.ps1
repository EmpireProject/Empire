Function Get-ComputerNameFromInstance {
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

Function  Get-SQLConnectionObject {
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
    Begin {           
        if($DAC){$DacConn = 'ADMIN:'}else{$DacConn = ''}
        if(-not $Database){$Database = 'Master'}
    } Process {
        if (-not $Instance) {
            $Instance = $env:COMPUTERNAME
        }
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
        if(-not $Username) {
            $AuthenticationType = "Current Windows Credentials"
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1"
        }
        if ($username -like "*\*") {
            $AuthenticationType = "Provided Windows Credentials"
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;uid=$Username;pwd=$Password;Connection Timeout=$TimeOut"
        }
        if (($username) -and ($username -notlike "*\*")) {
            $AuthenticationType = "Provided SQL Login"
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut"
        }
        return $Connection
    } End {                
    }
}

Function Get-SQLConnectionTest {
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
        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut
    )
    Begin {
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        if(-not $Instance) {
            $Instance = $env:COMPUTERNAME
        }
        if($DAC) {
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -DAC -TimeOut $TimeOut -Database $Database
        } else {
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut -Database $Database
        }
        try {
            $Connection.Open()
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')
            $Connection.Close()
            $Connection.Dispose()
        } catch {
            $ErrorMessage = $_.Exception.Message
            "$Instance : Connection Failed."
            "Error: $ErrorMessage"
        }
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
    } End {
        $TblResults
    }
}

Function  Get-SQLSession {
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
        HelpMessage = 'PrincipalName.')]
        [string]$PrincipalName
    )
    Begin {
        $TblSessions = New-Object -TypeName System.Data.DataTable
        $null = $TblSessions.Columns.Add('ComputerName')
        $null = $TblSessions.Columns.Add('Instance')
        $null = $TblSessions.Columns.Add('PrincipalSid')
        $null = $TblSessions.Columns.Add('PrincipalName')
        $null = $TblSessions.Columns.Add('OriginalPrincipalName')
        $null = $TblSessions.Columns.Add('SessionId')
        $null = $TblSessions.Columns.Add('SessionStartTime')
        $null = $TblSessions.Columns.Add('SessionLoginTime')
        $null = $TblSessions.Columns.Add('SessionStatus')
        if($PrincipalName) {
            $PrincipalNameFilter = " and login_name like '$PrincipalName'"
        } else {
            $PrincipalNameFilter = ''
        }
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        if(-not $Instance) {
            $Instance = $env:COMPUTERNAME
        }
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | ? -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection) {
            "$Instance : Connection Failed."
            return
        }
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            security_id as [PrincipalSid],
            login_name as [PrincipalName],
            original_login_name as [OriginalPrincipalName],
            session_id as [SessionId],
            last_request_start_time as [SessionStartTime],
            login_time as [SessionLoginTime],
            status as [SessionStatus]
            FROM    [sys].[dm_exec_sessions]
            ORDER BY status
        $PrincipalNameFilter"
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password
        $TblResults | % -Process {
            if ($NewSid) {
                $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
                if ($NewSid.length -le 10) {
    $Sid = [Convert]::ToInt32($NewSid,16)
                } else {
    $Sid = $NewSid
                }
                $null = $TblSessions.Rows.Add(
    [string]$_.ComputerName,
    [string]$_.Instance,
    $Sid,
    [string]$_.PrincipalName,
    [string]$_.OriginalPrincipalName,
    [string]$_.SessionId,
    [string]$_.SessionStartTime,
    [string]$_.SessionLoginTime,
    [string]$_.SessionStatus)
            }
        }
    } End {
        $TblSessions
    }
}

Function Get-SQLSysadminCheck {
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
        [string]$Instance
    )
    Begin {
        $TblSysadminStatus = New-Object -TypeName System.Data.DataTable
        if($CredentialName) {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        } else {
            $CredentialNameFilter = ''
        }
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        if(-not $Instance) {
            $Instance = $env:COMPUTERNAME
        }
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | 
        ? -FilterScript { $_.Status -eq 'Accessible' }
        if(-not $TestConnection) {
            "$Instance : Connection Failed."
            return
        }
        $Query = "SELECT '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            CASE
            WHEN IS_SRVROLEMEMBER('sysadmin') =  0 THEN 'No'
            ELSE 'Yes'
            END as IsSysadmin"
        $TblSysadminStatusTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password
        $TblSysadminStatus = $TblSysadminStatus + $TblSysadminStatusTemp
    } End {
        $TblSysadminStatus
    }
}

Function Get-SQLQuery {
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
    Begin {
        $TblQueryResults = New-Object -TypeName System.Data.DataTable
    } Process {      
        if($DAC){$Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut -DAC -Database $Database}
        else{$Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut -Database $Database}
        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(';')[0].split('=')[1]
        if($Query) {
            $Connection.Open()
            $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)
            try {
                $Results = $Command.ExecuteReader()             
                $TblQueryResults.Load($Results)  
            } catch {
                # pass
            }                    
            $Connection.Close()
            $Connection.Dispose() 
        }
        else{'No query provided to Get-SQLQuery function.';Break}
    } End {   
        if($ReturnError){$ErrorMessage}
        else{$TblQueryResults}                  
    }
}

Function Get-SQLServerInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
	ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,
        [Parameter(Mandatory = $false,
	ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,
        [Parameter(Mandatory = $false,
	ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance
    )
    Begin {
        $TblServerInfo = New-Object -TypeName System.Data.DataTable
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        if(-not $Instance) {
            $Instance = $env:COMPUTERNAME
        }
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | 
        ? -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection) {
            "$Instance : Connection Failed."
            return
        }
        $ActiveSessions = Get-SQLSession -Instance $Instance -Username $Username -Password $Password |
        ? -FilterScript { $_.SessionStatus -eq 'running' } | measure -Line | select -Property Lines -ExpandProperty Lines
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Username $Username -Password $Password
        if($IsSysadmin.IsSysadmin -eq 'Yes') {
            $SysadminSetup = "
                DECLARE @MachineType  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                @value_name		= N'ProductType',
                @value			= @MachineType output
                DECLARE @ProductName  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                @value_name		= N'ProductName',
                @value			= @ProductName output"
            $SysadminQuery = '  @MachineType as [OsMachineType],
                @ProductName as [OSVersionName],'
        } else {
            $SysadminSetup = ''
            $SysadminQuery = ''
        }

        $Query = "
            DECLARE @SQLServerInstance varchar(250)
            DECLARE @SQLServerServiceName varchar(250)
            if @@SERVICENAME = 'MSSQLSERVER'
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @SQLServerServiceName = 'MSSQLSERVER'
            END
            ELSE
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
            set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
            END

            DECLARE @ServiceaccountName varchar(250)
            EXECUTE master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

            DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT

            $SysadminSetup

            SELECT  '$ComputerName' as [ComputerName],
            @@servername as [Instance],
            DEFAULT_DOMAIN() as [DomainName],
            @SQLServerServiceName as [ServiceName],
            @ServiceAccountName as [ServiceAccount],
            (SELECT CASE @AuthenticationMode
            WHEN 1 THEN 'Windows Authentication'
            WHEN 2 THEN 'Windows and SQL Server Authentication'
            ELSE 'Unknown'
            END) as [AuthenticationMode],
            CASE  SERVERPROPERTY('IsClustered')
            WHEN 0
            THEN 'No'
            ELSE 'Yes'
            END as [Clustered],
            SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
            SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
            serverproperty('Edition') as [SQLServerEdition],
            SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
            SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
            $SysadminQuery
            RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
            SYSTEM_USER as [Currentlogin],
            '$IsSysadmin' as [IsSysadmin],
        '$ActiveSessions' as [ActiveSessions]"
        $TblServerInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password
        $TblServerInfo = $TblServerInfo + $TblServerInfoTemp
        ForEach ($Row in $TblServerInfo) {
            "ComputerName           : " + $Row.ComputerName 
            "Instance               : " + $Row.Instance 
            "DomainName             : " + $Row.DomainName 
            "ServiceName            : " + $Row.ServiceName 
            "ServiceAccount         : " + $Row.ServiceAccount 
            "AuthenticationMode     : " + $Row.AuthenticationMode 
            "Clustered              : " + $Row.Clustered 
            "SQLServerVersionNumber : " + $Row.SQLServerVersionNumber 
            "SQLServerMajorVersion  : " + $Row.SQLServerMajorVersion 
            "SQLServerEdition       : " + $Row.SQLServerEdition 
            "SQLServerServicePack   : " + $Row.SQLServerServicePack 
            "OSArchitecture         : " + $Row.OSArchitecture 
            "OsMachineType          : " + $Row.OsMachineType 
            "OSVersionName          : " + $Row.OSVersionName 
            "OsVersionNumber        : " + $Row.OsVersionNumber 
            "Currentlogin           : " + $Row.Currentlogin 
            "IsSysadmin             : " + $IsSysadmin.IsSysadmin 
            "ActiveSessions         : " + $Row.ActiveSessions 
            ""
        }

    } End {
    }
}

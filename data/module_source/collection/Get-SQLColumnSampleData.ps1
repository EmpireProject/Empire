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
Function Get-SQLConnectionObject {
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
        if (-not $Instance) { $Instance = $env:COMPUTERNAME }
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
        if(-not $Username) {
            $AuthenticationType = "Current Windows Credentials"
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1"
        }
        elseif ($username -like "*\*") {
            $AuthenticationType = "Provided Windows Credentials"
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;uid=$Username;pwd=$Password;Connection Timeout=$TimeOut"
        }
        elseif (($username) -and ($username -notlike "*\*")) {
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
        if(-not $Instance) { $Instance = $env:COMPUTERNAME }
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
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
Function Get-SQLQuery2 {
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
            "$Instance : Connection Success."
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
    } End {   
        if($ReturnError){$ErrorMessage}
        else{$TblQueryResults}                  
    }
}
Function  Get-SQLQuery {
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
        [string]$Instance,
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
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
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Return error message if exists.')]
        [switch]$ReturnError
    )

    Begin {
        $TblQueryResults = New-Object -TypeName System.Data.DataTable
    } Process {
        if($DAC) {
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut -DAC -Database $Database
        } else {
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -TimeOut $TimeOut -Database $Database
        }

        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(';')[0].split('=')[1]

        if($Query) {
            try {
                $Connection.Open()
                $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)
                $Results = $Command.ExecuteReader()
                $TblQueryResults.Load($Results)
                $Connection.Close()
                $Connection.Dispose()
            } catch {
                #Pass
            }
        }
        else
        {
            Write-Output -InputObject 'No query provided to Get-SQLQuery function.'
            Break
        }
    }

    End
    {
        $TblQueryResults
    }
}
Function Get-SQLColumn {
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
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Table name.')]
        [string]$TableName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter by exact column name.')]
        [string]$ColumnName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Column name using wildcards in search.  Supports comma seperated list.')]
        [string]$ColumnNameSearch,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblColumns = New-Object -TypeName System.Data.DataTable

        # Setup table filter
        if($TableName)
        {
            $TableNameFilter = " and TABLE_NAME like '%$TableName%'"
        }
        else
        {
            $TableNameFilter = ''
        }

        # Setup column filter
        if($ColumnName)
        {
            $ColumnFilter = " and column_name like '$ColumnName'"
        }
        else
        {
            $ColumnFilter = ''
        }

        # Setup column filter
        if($ColumnNameSearch)
        {
            $ColumnSearchFilter = " and column_name like '%$ColumnNameSearch%'"
        }
        else
        {
            $ColumnSearchFilter = ''
        }

        # Setup column search filter
        if($ColumnNameSearch)
        {
            $Keywords = $ColumnNameSearch.split(',')

            [int]$i = $Keywords.Count
            while ($i -gt 0)
            {
                $i = $i - 1
                $Keyword = $Keywords[$i]

                if($i -eq ($Keywords.Count -1))
                {
                    $ColumnSearchFilter = "and column_name like '%$Keyword%'"
                }
                else
                {
                    $ColumnSearchFilter = $ColumnSearchFilter + " or column_name like '%$Keyword%'"
                }
            }
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -DatabaseName $DatabaseName -HasAccess -NoDefaults
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -DatabaseName $DatabaseName -HasAccess
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG AS [DatabaseName],
                TABLE_SCHEMA AS [SchemaName],
                TABLE_NAME as [TableName],
                COLUMN_NAME as [ColumnName],
                DATA_TYPE as [ColumnDataType],
                CHARACTER_MAXIMUM_LENGTH as [ColumnMaxLength]
                FROM	[$DbName].[INFORMATION_SCHEMA].[COLUMNS] WHERE 1=1
                $ColumnSearchFilter
                $ColumnFilter
                $TableNameFilter
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password

            # Append results
            $TblColumns = $TblColumns + $TblResults
        }
    }

    End
    {
        # Return data
        $TblColumns
    }
}
Function Get-SQLDatabase {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,
        [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases the current user has access to.')]
        [switch]$HasAccess,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases owned by a sysadmin.')]
        [switch]$SysAdminOnly,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin {
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabases.Columns.Add('ComputerName')
        $null = $TblDatabases.Columns.Add('Instance')
        $null = $TblDatabases.Columns.Add('DatabaseId')
        $null = $TblDatabases.Columns.Add('DatabaseName')
        $null = $TblDatabases.Columns.Add('DatabaseOwner')
        $null = $TblDatabases.Columns.Add('OwnerIsSysadmin')
        $null = $TblDatabases.Columns.Add('is_trustworthy_on')
        $null = $TblDatabases.Columns.Add('is_db_chaining_on')
        $null = $TblDatabases.Columns.Add('is_broker_enabled')
        $null = $TblDatabases.Columns.Add('is_encrypted')
        $null = $TblDatabases.Columns.Add('is_read_only')
        $null = $TblDatabases.Columns.Add('create_date')
        $null = $TblDatabases.Columns.Add('recovery_model_desc')
        $null = $TblDatabases.Columns.Add('FileName')
        $null = $TblDatabases.Columns.Add('DbSizeMb')
        $null = $TblDatabases.Columns.Add('has_dbaccess')

        if($DatabaseName) {
            $DatabaseFilter = " and a.name like '$DatabaseName'"
        } else {
            $DatabaseFilter = ''
        }

        if($NoDefaults) {
            $NoDefaultsFilter = " and a.name not in ('master','tempdb','msdb','model')"
        } else {
            $NoDefaultsFilter = ''
        }

        if($HasAccess) {
            $HasAccessFilter = ' and HAS_DBACCESS(a.name)=1'
        } else {
            $HasAccessFilter = ''
        }

        if($SysAdminOnly) {
            $SysAdminOnlyFilter = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        } else {
            $SysAdminOnlyFilter = ''
        }
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        if(-not $Instance) {
            $Instance = $env:COMPUTERNAME
        }

        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($TestConnection) {
            if( -not $SuppressVerbose) {
                "$Instance : Connection Success."
            }
        } else {
            if( -not $SuppressVerbose) {
                "$Instance : Connection Failed."
            }
            return
        }

        $SQLServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password
        if($SQLServerInfo.SQLServerVersionNumber) {
            $SQLVersionShort = $SQLServerInfo.SQLServerVersionNumber.Split('.')[0]
        }

        $QueryStart = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            a.database_id as [DatabaseId],
            a.name as [DatabaseName],
            SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
            IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
            a.is_trustworthy_on,
        a.is_db_chaining_on,"

        if([int]$SQLVersionShort -ge 10) {
            $QueryVerSpec = '
                a.is_broker_enabled,
                a.is_encrypted,
            a.is_read_only,'
        }

        $QueryEnd = '
            a.create_date,
            a.recovery_model_desc,
            b.filename as [FileName],
            (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
            from sys.master_files where name like a.name) as [DbSizeMb],
            HAS_DBACCESS(a.name) as [has_dbaccess]
            FROM [sys].[databases] a
        INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1'

        $Filters = "
            $DatabaseFilter
            $NoDefaultsFilter
            $HasAccessFilter
            $SysAdminOnlyFilter
        ORDER BY a.database_id"

        $Query = "$QueryStart $QueryVerSpec $QueryEnd $Filters"

        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password

        $TblResults | ForEach-Object -Process {
            if([int]$SQLVersionShort -ge 10) {
                $is_broker_enabled = $_.is_broker_enabled
                $is_encrypted = $_.is_encrypted
                $is_read_only = $_.is_read_only
            } else {
                $is_broker_enabled = 'NA'
                $is_encrypted = 'NA'
                $is_read_only = 'NA'
            }

            $null = $TblDatabases.Rows.Add(
                $_.ComputerName,
                $_.Instance,
                $_.DatabaseId,
                $_.DatabaseName,
                $_.DatabaseOwner,
                $_.OwnerIsSysadmin,
                $_.is_trustworthy_on,
                $_.is_db_chaining_on,
                $is_broker_enabled,
                $is_encrypted,
                $is_read_only,
                $_.create_date,
                $_.recovery_model_desc,
                $_.FileName,
                $_.DbSizeMb,
                $_.has_dbaccess
            )
        }

    } End {
        $TblDatabases
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
        $TblServerInfo
    } End {
    }
}
Function Get-SQLSession {
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
                    [string]$_.SessionStatus
                )
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
Function Get-SQLColumnSampleData {
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
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$SampleSize = 1,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Comma seperated list of keywords to search for.')]
        [string]$Keywords = 'Password',
        [Parameter(Mandatory = $false,
        HelpMessage = 'Database name to filter on.')]
        [string]$DatabaseName,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Use Luhn formula to check if sample is a valid credit card.')]
        [switch]$ValidateCC,
        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults
    )
    Begin {
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Database')
        $null = $TblData.Columns.Add('Schema')
        $null = $TblData.Columns.Add('Table')
        $null = $TblData.Columns.Add('Column')
        $null = $TblData.Columns.Add('Sample')
        $null = $TblData.Columns.Add('RowCount')
        if($ValidateCC) { $null = $TblData.Columns.Add('IsCC') }
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        if(-not $Instance) { $Instance = $env:COMPUTERNAME }
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | ? -FilterScript { $_.Status -eq 'Accessible' }
        if(-not $TestConnection) {
            "$Instance : CONNECTION FAILED"
            Return
        } else {
            "$Instance : START SEARCH DATA BY COLUMN "
            "$Instance : - Connection Success. "
            "$Instance : - Searching for column names that match criteria... "
            if($NoDefaults) {
                $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -NoDefaults
            } else {
                $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -DatabaseName $DatabaseName -ColumnNameSearch $Keywords 
            }
        }
        if($Columns) {
            $Columns | % -Process {
                Write-Verbose $_.DatabaseName
                $sDatabaseName = $_.DatabaseName
                $sSchemaName = $_.SchemaName
                $sTableName = $_.TableName
                $sColumnName = $_.ColumnName
                $AffectedColumn = "[$sDatabaseName].[$sSchemaName].[$sTableName].[$sColumnName]"
                $AffectedTable = "[$sDatabaseName].[$sSchemaName].[$sTableName]"
                $Query = "USE $sDatabaseName; SELECT TOP $SampleSize [$sColumnName] FROM $AffectedTable WHERE [$sColumnName] is not null"
                $QueryRowCount = "USE $sDatabaseName; SELECT count(CAST([$sColumnName] as VARCHAR(200))) as NumRows FROM $AffectedTable WHERE [$sColumnName] is not null"
                
                "$Instance : - Table match: $AffectedTable "
                "$Instance : - Column match: $AffectedColumn "
                "$Instance : - Selecting $SampleSize rows of data sample from column $AffectedColumn. "

                $RowCountOut = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Query $QueryRowCount 
                $RowCount = $RowCountOut.NumRows
                $SQLQuery = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Query $Query
                $SQLQuery.$sColumnName | % -Process {
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount)
                }
            }
        } else {
                "$Instance : - No columns were found that matched the search. "
        }
        "$Instance : END SEARCH DATA BY COLUMN "
    } End {
        ForEach ($Row in $TblData) {
            "ComputerName : " + $Row.ComputerName 
            "Instance     : " + $Row.Instance 
            "Database     : " + $Row.Database 
            "Schema       : " + $Row.Schema 
            "Table        : " + $Row.Table 
            "Column       : " + $Row.Column 
            "Sample       : " + $Row.Sample 
            "RowCount     : " + $Row.RowCount 
            ""
        }
    }
}
Function Get-ComputerNameFromInstance {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    )
    If ($Instance) {
        $ComputerName = $Instance.split('\')[0].split(',')[0]
    } else {
        $ComputerName = $env:COMPUTERNAME
    }
    Return $ComputerName
}
Function  Get-SQLConnectionTest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
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
        [string]$TimeOut,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
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
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
        }
    } End {
        $TblResults
    }
}
Function  Get-SQLSession {

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
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'PrincipalName.')]
        [string]$PrincipalName,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
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

        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection) {
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

        $TblResults | ForEach-Object -Process {
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
    } End {
        $TblSessions
    }
}
Function  Get-SQLSysadminCheck {
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
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
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

        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection) {
            return
        }

        $Query = "SELECT    '$ComputerName' as [ComputerName],
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
                ValueFromPipelineByPropertyName = $true,
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
        if($DAC) {
            $DacConn = 'ADMIN:'
        } else {
            $DacConn = ''
        }

        if(-not $Database) {
            $Database = 'Master'
        }
    } Process {
        if ( -not $Instance) {
            $Instance = $env:COMPUTERNAME
        }
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
        if (-not $Username) {
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
        } else {
            Write-Output -InputObject 'No query provided to Get-SQLQuery function.'
            Break
        }
    } End {
        $TblQueryResults
    }
}
Function  Get-SQLServerInfo {
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
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin {
        $TblServerInfo = New-Object -TypeName System.Data.DataTable
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection) {
            return
        }

        $ActiveSessions = Get-SQLSession -Instance $Instance -Username $Username -Password $Password |
        Where-Object -FilterScript {
            $_.SessionStatus -eq 'running'
        } | Measure-Object -Line | Select-Object -Property Lines -ExpandProperty Lines

        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Username $Username -Password $Password | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
        if($IsSysadmin -eq 'Yes') {
            $SysadminSetup = "
                -- Get machine type
                DECLARE @MachineType  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                @value_name		= N'ProductType',
                @value			= @MachineType output
                -- Get OS version
                DECLARE @ProductName  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                @value_name		= N'ProductName',
                @value			= @ProductName output"
                $SysadminQuery  = '  @MachineType as [OsMachineType],
                @ProductName as [OSVersionName],'
        } else {
            $SysadminSetup = ''
            $SysadminQuery = ''
        }

        $Query = "  -- Get SQL Server Information
            -- Get SQL Server Service Name and Path
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
            -- Get SQL Server Service Account
            DECLARE @ServiceaccountName varchar(250)
            EXECUTE master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'
            -- Get authentication mode
            DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT
            -- Grab additional information as sysadmin
            $SysadminSetup
            -- Return server and version information
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
    } End {
        $TblServerInfo
    }
}
Function  Get-SQLServerLoginDefaultPw {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin {
        # Table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblResults.Columns.Add('Computer') | Out-Null
        $TblResults.Columns.Add('Instance') | Out-Null
        $TblResults.Columns.Add('Username') | Out-Null
        $TblResults.Columns.Add('Password') | Out-Null 
        $TblResults.Columns.Add('IsSysAdmin') | Out-Null

        # Create table for database of defaults
        $DefaultPasswords = New-Object System.Data.DataTable
        $DefaultPasswords.Columns.Add('Instance') | Out-Null
        $DefaultPasswords.Columns.Add('Username') | Out-Null
        $DefaultPasswords.Columns.Add('Password') | Out-Null        

        # Populate DefaultPasswords data table
        $DefaultPasswords.Rows.Add("ACS","ej","ej") | Out-Null
        $DefaultPasswords.Rows.Add("ACT7","sa","sage") | Out-Null
        $DefaultPasswords.Rows.Add("AOM2","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("ARIS","ARIS9","*ARIS!1dm9n#") | out-null
        $DefaultPasswords.Rows.Add("AutodeskVault","sa","AutodeskVault@26200") | Out-Null      
        $DefaultPasswords.Rows.Add("BOSCHSQL","sa","RPSsql12345") | Out-Null
        $DefaultPasswords.Rows.Add("BPASERVER9","sa","AutoMateBPA9") | Out-Null
        $DefaultPasswords.Rows.Add("CDRDICOM","sa","CDRDicom50!") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL08","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CounterPoint","sa","CounterPoint8") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","ELNAdmin","ELNAdmin") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","sa","CambridgeSoft_SA") | Out-Null
        $DefaultPasswords.Rows.Add("CADSQL","CADSQLAdminUser","Cr41g1sth3M4n!") | Out-Null
        $DefaultPasswords.Rows.Add("DHLEASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("DPM","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("DVTEL","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("EASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("ECC","sa","Webgility2011") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","e+C0py2007_@x","e+C0py2007_@x") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","sa","ecopy") | Out-Null
        $DefaultPasswords.Rows.Add("Emerson2012","sa","42Emerson42Eme") | Out-Null
        $DefaultPasswords.Rows.Add("HDPS","sa","sa") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","Hpdsdb000001") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","hpdss") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","msi","keyboa5") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("INTRAVET","sa","Webster#1") | Out-Null
        $DefaultPasswords.Rows.Add("MYMOVIES","sa","t9AranuHA7") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","pcAmer1ca") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","PCAmerica") | Out-Null
        $DefaultPasswords.Rows.Add("PRISM","sa","SecurityMaster08") | Out-Null
        $DefaultPasswords.Rows.Add("RMSQLDATA","Super","Orange") | out-null
        $DefaultPasswords.Rows.Add("RTCLOCAL","sa","mypassword") | Out-Null
        $DefaultPasswords.Rows.Add("SALESLOGIX","sa","SLXMaster") | Out-Null
        $DefaultPasswords.Rows.Add("SIDEXIS_SQL","sa","2BeChanged") | Out-Null
        $DefaultPasswords.Rows.Add("SQL2K5","ovsd","ovsd") | Out-Null
        $DefaultPasswords.Rows.Add("SQLEXPRESS","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("STANDARDDEV2014","test","test") | Out-Null 
        $DefaultPasswords.Rows.Add("TEW_SQLEXPRESS","tew","tew") | Out-Null
        $DefaultPasswords.Rows.Add("vocollect","vocollect","vocollect") | Out-Null
        $DefaultPasswords.Rows.Add("VSDOTNET","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("VSQL","sa","111") | Out-Null

        $PwCount = $DefaultPasswords | measure | select count -ExpandProperty count
    } Process {
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        if (-not $Instance) {
            $Instance = $env:COMPUTERNAME
        }
       
        # Grab only the instance name
        $TargetInstance = $Instance.Split("\")[1]

        # Bypass ports and default instances
        if (-not $TargetInstance) {
            "$Instance : No instance match found."
            return
        }
        $TblResultsTemp = $DefaultPasswords | Where-Object { $_.instance -eq "$TargetInstance"}        

        if ($TblResultsTemp) {
            "$Instance : Confirmed instance match."            
        } else {
            "$Instance : No instance match found."
            return  
        }
        $CurrentUsername = $TblResultsTemp.username
        $CurrentPassword = $TblResultsTemp.password
        $LoginTest = Get-SQLServerInfo -Instance $instance -Username $CurrentUsername -Password $CurrentPassword -SuppressVerbose
        if ($LoginTest) {
            "$Instance : Confirmed default credentials - $CurrentUsername/$CurrentPassword"
            $SysadminStatus = $LoginTest | select IsSysadmin -ExpandProperty IsSysadmin                   
            $TblResults.Rows.Add(
                $ComputerName,
                $Instance,
                $CurrentUsername,
                $CurrentPassword,
                $SysadminStatus
            ) | Out-Null
        } else {
            "$Instance : No credential matches were found."
        }
    } End {
        ForEach ($Result in $TblResults) {
            "Computer   : " + $Result.Computer 
            "Instance   : " + $Result.Instance 
            "Username   : " + $Result.Username 
            "Password   : " + $Result.Password 
            "IsSysAdmin : " + $Result.IsSysAdmin 
            ""
        }
    }
}
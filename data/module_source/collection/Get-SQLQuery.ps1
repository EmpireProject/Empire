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
            "$Instance : Connection Success."
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
        else{$TblQueryResults.Column1}                  
    }
}

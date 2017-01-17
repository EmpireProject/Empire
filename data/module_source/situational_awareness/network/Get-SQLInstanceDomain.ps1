Function Get-DomainObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,
        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',
        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,
        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin {
        if($Username -and $Password) {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }
        if ($DomainController) {
            $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password).distinguishedname
            if($LdapPath) {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController$LdapPath", $Credential.UserName, $Credential.GetNetworkCredential().Password
            } else {
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }
            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        } else {
            $objDomain = ([ADSI]'').distinguishedName
            if($LdapPath) {
                $LdapPath = $LdapPath+','+$objDomain;$objDomainPath  = [ADSI]"LDAP://$LdapPath"
            } else {
                $objDomainPath  = [ADSI]''
            }
            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    } Process {
        try {
            $objSearcher.FindAll() | % -Process {$_}
        } catch {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }  End {
    }
}

Function Get-DomainSpn {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,
        [Parameter(Mandatory = $false,
        HelpMessage = 'SPN service code.')]
        [string]$SpnService,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )
    Begin {
        if(-not $SuppressVerbose){'Getting domain SPNs...'}
        $TableDomainSpn = New-Object -TypeName System.Data.DataTable
        $null = $TableDomainSpn.Columns.Add('UserSid')
        $null = $TableDomainSpn.Columns.Add('User')
        $null = $TableDomainSpn.Columns.Add('UserCn')
        $null = $TableDomainSpn.Columns.Add('Service')
        $null = $TableDomainSpn.Columns.Add('ComputerName')
        $null = $TableDomainSpn.Columns.Add('Spn')
        $null = $TableDomainSpn.Columns.Add('LastLogon')
        $null = $TableDomainSpn.Columns.Add('Description')
        $TableDomainSpn.Clear()
    } Process {
        try {
            $SpnFilter = ''
            if($DomainAccount) {
                $SpnFilter = "(objectcategory=person)(SamAccountName=$DomainAccount)"
            }
            if($ComputerName) {
                $ComputerSearch = "$ComputerName`$"
                $SpnFilter = "(objectcategory=computer)(SamAccountName=$ComputerSearch)"
            }
            $SpnResults = Get-DomainObject -LdapFilter "(&(servicePrincipalName=$SpnService*)$SpnFilter)" -DomainController $DomainController -Username $Username -Password $Password
            $SpnResults | % -Process {
                [string]$SidBytes = [byte[]]"$($_.Properties.objectsid)".split(' ')
                [string]$SidString = $SidBytes -replace ' ', ''
                $Spn = $_.properties.serviceprincipalname.split(',')
                foreach ($item in $Spn) {
                    $SpnServer = $item.split('/')[1].split(':')[0].split(' ')[0]
                    $SpnService = $item.split('/')[0]
                    if ($_.properties.lastlogon) {
                        $LastLogon = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    } else {
                        $LastLogon = ''
                    }
                    $null = $TableDomainSpn.Rows.Add(
                        [string]$SidString,
                        [string]$_.properties.samaccountname,
                        [string]$_.properties.cn,
                        [string]$SpnService,
                        [string]$SpnServer,
                        [string]$item,
                        $LastLogon,
                        [string]$_.properties.description
                    )
                }
            }
        } catch {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    } End {
        if ($TableDomainSpn.Rows.Count -gt 0) {
            $TableDomainSpnCount = $TableDomainSpn.Rows.Count
            if(-not $SuppressVerbose) {
                "$TableDomainSpnCount SPNs found on servers that matched search criteria."
            }
            Return $TableDomainSpn
        } else {
            '0 SPNs found.'
        }
    }
}

Function  Get-SQLInstanceDomain {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Performs UDP scan of servers managing SQL Server clusters.')]
        [switch]$CheckMgmt,
        [Parameter(Mandatory = $false,
        HelpMessage = 'Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 3
    )
    Begin {
        $TblSQLServerSpns = New-Object -TypeName System.Data.DataTable
        $null = $TblSQLServerSpns.Columns.Add('ComputerName')
        $null = $TblSQLServerSpns.Columns.Add('Instance')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountSid')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccount')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountCn')
        $null = $TblSQLServerSpns.Columns.Add('Service')
        $null = $TblSQLServerSpns.Columns.Add('Spn')
        $null = $TblSQLServerSpns.Columns.Add('LastLogon')
        $null = $TblSQLServerSpns.Columns.Add('Description')
    } Process {
        "Grabbing SPNs from the domain for SQL Servers (MSSQL*)..."
        $TblSQLServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSSQL*' -SuppressVerbose | 
        ? -FilterScript { $_.service -like 'MSSQL*' }
        "Parsing SQL Server instances from SPNs..."
        $TblSQLServers | % -Process {
            $Spn = $_.Spn
            $Instance = $Spn.split('/')[1].split(':')[1]
            $Value = 0
            if([int32]::TryParse($Instance,[ref]$Value)) {
                $SpnServerInstance = $Spn -replace ':', ','
            } else {
                $SpnServerInstance = $Spn -replace ':', '\'
            }
            $SpnServerInstance = $SpnServerInstance -replace 'MSSQLSvc/', ''
            $null = $TblSQLServerSpns.Rows.Add(
                [string]$_.ComputerName,
                [string]$SpnServerInstance,
                $_.UserSid,
                [string]$_.User,
                [string]$_.Usercn,
                [string]$_.Service,
                [string]$_.Spn,
                $_.LastLogon,
                [string]$_.Description)
        }
        if($CheckMgmt) {
            "Grabbing SPNs from the domain for Servers managing SQL Server clusters (MSServerClusterMgmtAPI)..."
            $TblMgmtServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSServerClusterMgmtAPI' -SuppressVerbose |
            ? -FilterScript { $_.ComputerName -like '*.*' } | select -Property ComputerName -Unique | sort -Property ComputerName
            "Performing a UDP scan of management servers to obtain managed SQL Server instances..."
            $TblMgmtSQLServers = $TblMgmtServers | select -Property ComputerName -Unique | Get-SQLInstanceScanUDP -UDPTimeOut $UDPTimeOut
        }
    } End {
        if($CheckMgmt) {
            "Parsing SQL Server instances from the UDP scan..."
            $Tbl1 = $TblMgmtSQLServers |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl2 = $TblSQLServerSpns |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl3 = $Tbl1 + $Tbl2
            $InstanceCount = $Tbl3.rows.count
            "$InstanceCount instances were found."
            ForEach ($Row in $Tbl3){
                "ComputerName     : " + $Row.ComputerName 
                "Instance         : " + $Row.Instance 
                ""
            }
            $Tbl3
        } else {
            $InstanceCount = $TblSQLServerSpns.rows.count
            "$InstanceCount instances were found."
            ForEach ($Row in $TblSQLServerSpns) {
                "ComputerName     : " + $Row.ComputerName 
                "Instance         : " + $Row.Instance 
                "DomainAccountSid : " + $Row.DomainAccountSid 
                "DomainAccount    : " + $Row.DomainAccount 
                "DomainAccountCn  : " + $Row.DomainAccountCn 
                "Service          : " + $Row.Service 
                "Spn              : " + $Row.Spn 
                "LastLogon        : " + $Row.LastLogon 
                "Description      : " + $Row.Description 
                ""
            }
            $TblSQLServerSpns
        }
    }
}
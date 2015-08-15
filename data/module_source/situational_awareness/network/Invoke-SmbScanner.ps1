function Invoke-SMBScanner {
<#
.SYNOPSIS

    Tests a username/password combination across a number of machines.
    If no machines are specified, the domain will be queries for active machines.
    For domain accounts, use the form DOMAIN\username for username specifications.

    Author: Chris Campbell (@obscuresec), mods by @harmj0y
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 0.1.0
 
.DESCRIPTION

    Tests a username/password combination across a number of machines.
    If no machines are specified, the domain will be queries for active machines.
    For domain accounts, use the form DOMAIN\username for username specifications.

.EXAMPLE

    PS C:\> Invoke-SMBScanner -ComputerName WINDOWS4 -UserName test123 -Password password123456! -Domain

    ComputerName            Password                                Username
    ----                    --------                                --------
    WINDOWS4                password123456!                         test123


.EXAMPLE

    PS C:\> Get-Content 'c:\demo\computers.txt' | Invoke-SMBScanner -UserName dev\\test -Password 'Passsword123456!'
    
    ComputerName            Password                                Username
    ----                    --------                                --------
    WINDOWS3                password123456!                         dev\\test
    WINDOWS4                password123456!                         dev\\test

    ...


.LINK
    

#>
    
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $False,ValueFromPipeline=$True)]
        [String] $ComputerName,

        [parameter(Mandatory = $True)]
        [String] $UserName,

        [parameter(Mandatory = $True)]
        [String] $Password,

        [parameter(Mandatory = $False)]
        [Switch] $NoPing
    )

    Begin {
        Set-StrictMode -Version 2
        #try to load assembly
        Try {Add-Type -AssemblyName System.DirectoryServices.AccountManagement}
        Catch {Write-Error $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage}
    }

    Process {

        $ComputerNames = @()

        # if no computer names are specified, try to query the current domain
        if(-not $ComputerName){
            Write-Verbose "Querying the domain for active machines."
            "Querying the domain for active machines."

            $ComputerNames = [array] ([adsisearcher]'objectCategory=Computer').Findall() | ForEach {$_.properties.cn}

            Write-Verbose "Retrived $($ComputerNames.Length) systems from the domain."
        }
        else {
            $ComputerNames = @($ComputerName)
        }

        foreach ($Computer in $ComputerNames){     

            Try {
                
                Write-Verbose "Checking: $Computer"

                $up = $true
                if(-not $NoPing){
                    $up = Test-Connection -count 1 -Quiet -ComputerName $Computer 
                }
                if($up){

                    if ($Username.contains("\\")) {
                        # if there's a \ in the username, assume we're checking a domain account
                        $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                    }
                    else{
                        # otherwise assume a local account
                        $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
                    }

                    $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $Computer)
                
                    $Valid = $PrincipalContext.ValidateCredentials($Username, $Password).ToString()
                    
                    If ($Valid) {
                        Write-Verbose "SUCCESS: $Username works with $Password on $Computer"

                        $out = new-object psobject
                        $out | add-member Noteproperty 'ComputerName' $Computer
                        $out | add-member Noteproperty 'Username' $Username
                        $out | add-member Noteproperty 'Password' $Password
                        $out
                    }
                
                    Else {
                        Write-Verbose "FAILURE: $Username did not work with $Password on $ComputerName"
                    }
                }
            }

            Catch {Write-Error $($Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage)}
        }
    }
}
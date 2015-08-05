
function Get-NetDomainController {
    <#
        .SYNOPSIS
        Return the current domain controllers for the active domain.

        .PARAMETER Domain
        The domain to query for domain controllers. If not supplied, the
        current domain is used.

        .EXAMPLE
        > Get-NetDomainController
        Returns the domain controllers for the current computer's domain.
        Approximately equivialent to the hostname given in the LOGONSERVER
        environment variable.

        .EXAMPLE
        > Get-NetDomainController -Domain test
        Returns the domain controllers for the domain "test".
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $d = Get-NetDomain -Domain $Domain
    if($d){
        $d.DomainControllers
    }
}


function Get-NetDomain {
    <#
        .SYNOPSIS
        Returns the name of the current user's domain.

        .PARAMETER Domain
        The domain to query return. If not supplied, the
        current domain is used.

        .EXAMPLE
        > Get-NetDomain
        Return the current domain.

        .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>

    [CmdletBinding()]
    param(
        [String]
        $Domain
    )

    if($Domain -and ($Domain -ne "")){
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else{
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}


function Get-NetUser {
    <#
        .SYNOPSIS
        Query information for a given user or users in the domain.

        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current
        domain for all users. Another domain can be specified to
        query for users across a trust.
        This is a replacement for "net users /domain"

        .PARAMETER UserName
        Username filter string, wildcards accepted.

        .PARAMETER Domain
        The domain to query for users. If not supplied, the
        current domain is used.

        .PARAMETER OU
        The OU to pull users from.

        .PARAMETER Filter
        The complete LDAP query string to use to query for users.

        .EXAMPLE
        > Get-NetUser
        Returns the member users of the current domain.

        .EXAMPLE
        > Get-NetUser -Domain testing
        Returns all the members in the "testing" domain.
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $UserName,

        [string]
        $OU,

        [string]
        $Filter,

        [string]
        $Domain
    )
    process {
        # if a domain is specified, try to grab that domain
        if ($Domain){

            # try to grab the primary DC for the current domain
            try{
                $PrimaryDC = ([Array](Get-NetDomainController))[0].Name
            }
            catch{
                $PrimaryDC = $Null
            }

            try {
                # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
                $dn = "DC=$($Domain.Replace('.', ',DC='))"

                # if we have an OU specified, be sure to through it in
                if($OU){
                    $dn = "OU=$OU,$dn"
                }

                # if we could grab the primary DC for the current domain, use that for the query
                if ($PrimaryDC){
                    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
                }
                else{
                    # otherwise try to connect to the DC for the target domain
                    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                }

                # check if we're using a username filter or not
                if($UserName){
                    # samAccountType=805306368 indicates user objects
                    $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName))"
                }
                elseif($Filter){
                    # filter is something like (samAccountName=*blah*)
                    $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
                }
                else{
                    $UserSearcher.filter='(&(samAccountType=805306368))'
                }
                $UserSearcher.PageSize = 200
                $UserSearcher.FindAll() | ForEach-Object {
                    # for each user/member, do a quick adsi object grab
                    $properties = $_.Properties
                    $out = New-Object psobject
                    $properties.PropertyNames | % {
                        if ($_ -eq "objectsid"){
                            # convert the SID to a string
                            $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                        }
                        elseif($_ -eq "objectguid"){
                            # convert the GUID to a string
                            $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                        }
                        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") ){
                            $out | Add-Member Noteproperty $_ ([datetime]::FromFileTime(($properties[$_][0])))
                        }
                        else {
                            if ($properties[$_].count -eq 1) {
                                $out | Add-Member Noteproperty $_ $properties[$_][0]
                            }
                            else {
                                $out | Add-Member Noteproperty $_ $properties[$_]
                            }
                        }
                    }
                    $out
                }
            }
            catch{
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            }
        }
        else{
            # otherwise, use the current domain
            if($UserName){
                $UserSearcher = [adsisearcher]"(&(samAccountType=805306368)(samAccountName=*$UserName*))"
            }
            # if we're specifying an OU
            elseif($OU){
                $dn = "OU=$OU," + ([adsi]'').distinguishedname
                $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                $UserSearcher.filter='(&(samAccountType=805306368))'
            }
            # if we're specifying a specific LDAP query string
            elseif($Filter){
                # filter is something like (samAccountName=*blah*)
                $UserSearcher = [adsisearcher]"(&(samAccountType=805306368)$Filter)"
            }
            else{
                $UserSearcher = [adsisearcher]'(&(samAccountType=805306368))'
            }
            $UserSearcher.PageSize = 200

            $UserSearcher.FindAll() | ForEach-Object {
                # for each user/member, do a quick adsi object grab
                $properties = $_.Properties
                $out = New-Object psobject
                $properties.PropertyNames | % {
                    if ($_ -eq "objectsid"){
                        # convert the SID to a string
                        $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                    }
                    elseif($_ -eq "objectguid"){
                        # convert the GUID to a string
                        $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
                    }
                    elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") ){
                        $out | Add-Member Noteproperty $_ ([datetime]::FromFileTime(($properties[$_][0])))
                    }
                    else {
                        if ($properties[$_].count -eq 1) {
                            $out | Add-Member Noteproperty $_ $properties[$_][0]
                        }
                        else {
                            $out | Add-Member Noteproperty $_ $properties[$_]
                        }
                    }
                }
                $out
            }
        }
    }
}

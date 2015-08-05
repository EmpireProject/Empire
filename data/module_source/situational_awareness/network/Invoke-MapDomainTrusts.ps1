
# Invoke-MapDomainTrusts.ps1
# part of PowerView in Veil's PowerTools
#   https://github.com/Veil-Framework/PowerTools/

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

function Get-NetDomainTrusts {
    <#
        .SYNOPSIS
        Return all domain trusts for the current domain or
        a specified domain.

        .PARAMETER Domain
        The domain whose trusts to enumerate. If not given,
        uses the current domain.

        .EXAMPLE
        > Get-NetDomainTrusts
        Return domain trusts for the current domain.

        .EXAMPLE
        > Get-NetDomainTrusts -Domain "test"
        Return domain trusts for the "test" domain.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $d = Get-NetDomain -Domain $Domain
    if($d){
        $d.GetAllTrustRelationships()
    }
}


function Get-NetDomainTrustsLDAP {
    <#
        .SYNOPSIS
        Return all domain trusts for the current domain or
        a specified domain using LDAP queries. This is potentially
        less accurate than the Get-NetDomainTrusts function, but
        can be relayed through your current domain controller
        in cases where you can't reach a remote domain directly.

        .PARAMETER Domain
        The domain whose trusts to enumerate. If not given,
        uses the current domain.

        .EXAMPLE
        > Get-NetDomainTrustsLDAP
        Return domain trusts for the current domain.

        .EXAMPLE
        > Get-NetDomainTrustsLDAP -Domain "test"
        Return domain trusts for the "test" domain.
    #>

    [CmdletBinding()]
    param(
        [string]
        $Domain
    )

    $TrustSearcher = $Null

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if ($PrimaryDC){
                $TrustSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
            }
            else{
                # otherwise default to connecting to the DC for the target domain
                $TrustSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }

            $TrustSearcher.filter = '(&(objectClass=trustedDomain))'
            $TrustSearcher.PageSize = 200
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            $TrustSearcher = $Null
        }
    }
    else{
        $Domain = (Get-NetDomain).Name
        $TrustSearcher = [adsisearcher]'(&(objectClass=trustedDomain))'
        $TrustSearcher.PageSize = 200
    }

    if($TrustSearcher){
        $TrustSearcher.FindAll() | ForEach-Object {
            $props = $_.Properties
            $out = New-Object psobject
            Switch ($props.trustattributes)
            {
                4  { $attrib = "External"}
                16 { $attrib = "CrossLink"}
                32 { $attrib = "ParentChild"}
                64 { $attrib = "External"}
                68 { $attrib = "ExternalQuarantined"}
                Default { $attrib = "unknown trust attribute number: $($props.trustattributes)" }
            }
            Switch ($props.trustdirection){
                0 {$direction = "Disabled"}
                1 {$direction = "Inbound"}
                2 {$direction = "Outbound"}
                3 {$direction = "Bidirectional"}
            }
            $out | Add-Member Noteproperty 'SourceName' $domain
            $out | Add-Member Noteproperty 'TargetName' $props.name[0]
            $out | Add-Member Noteproperty 'TrustType' "$attrib"
            $out | Add-Member Noteproperty 'TrustDirection' "$direction"
            $out
        }
    }
}


function Invoke-MapDomainTrusts {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships.

        .DESCRIPTION
        This function gets all trusts for the current domain,
        and tries to get all trusts for each domain it finds.

        .EXAMPLE
        > Invoke-MapDomainTrusts
        Return a "domain1,domain2,trustType,trustDirection" list

        .LINK
        http://blog.harmj0y.net/
    #>

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            try{
                # get all the trusts for this domain
                $trusts = Get-NetDomainTrusts -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $source = $trust.SourceName
                        $target = $trust.TargetName
                        $type = $trust.TrustType
                        $direction = $trust.TrustDirection

                        # make sure we process the target
                        $domains.push($target) | out-null

                        # build the nicely-parsable custom output object
                        $out = new-object psobject
                        $out | add-member Noteproperty 'SourceDomain' $source
                        $out | add-member Noteproperty 'TargetDomain' $target
                        $out | add-member Noteproperty 'TrustType' "$type"
                        $out | add-member Noteproperty 'TrustDirection' "$direction"
                        $out
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function Invoke-MapDomainTrustsLDAP {
    <#
        .SYNOPSIS
        Try to map all transitive domain trust relationships
        through LDAP queries.

        .EXAMPLE
        > Invoke-MapDomainTrustsLDAP
        Return a "domain1,domain2,trustType,trustDirection" list

        .LINK
        http://blog.harmj0y.net/
    #>

    # keep track of domains seen so we don't hit infinite recursion
    $seenDomains = @{}

    # our domain status tracker
    $domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $currentDomain = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $domains.push($currentDomain)

    while($domains.Count -ne 0){

        $d = $domains.Pop()

        # if we haven't seen this domain before
        if (-not $seenDomains.ContainsKey($d)) {

            # mark it as seen in our list
            $seenDomains.add($d, "") | out-null

            try{
                # get all the trusts for this domain through LDAP queries
                $trusts = Get-NetDomainTrustsLDAP -Domain $d
                if ($trusts){

                    # enumerate each trust found
                    foreach ($trust in $trusts){
                        $source = $trust.SourceName
                        $target = $trust.TargetName
                        $type = $trust.TrustType
                        $direction = $trust.TrustDirection

                        # make sure we process the target
                        $domains.push($target) | out-null

                        # build the nicely-parsable custom output object
                        $out = new-object psobject
                        $out | add-member Noteproperty 'SourceDomain' $source
                        $out | add-member Noteproperty 'TargetDomain' $target
                        $out | add-member Noteproperty 'TrustType' $type
                        $out | add-member Noteproperty 'TrustDirection' $direction
                        $out
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


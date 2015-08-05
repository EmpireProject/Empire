
function Convert-SidToName {
    <#
    .SYNOPSIS
    Converts a security identifier (SID) to a group/user name.
    
    .PARAMETER SID
    The SID to convert.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $SID
    )

    process {
        try {
            $obj = (New-Object System.Security.Principal.SecurityIdentifier($SID))
            $obj.Translate( [System.Security.Principal.NTAccount]).Value
        }
        catch {
            Write-Warning "invalid SID"
        }
    }
}


function Get-NetGroup {
    <#
        .SYNOPSIS
        Gets a list of all current users in a specified domain group.

        .DESCRIPTION
        This function users [ADSI] and LDAP to query the current AD context
        or trusted domain for users in a specified group. If no GroupName is
        specified, it defaults to querying the "Domain Admins" group.
        This is a replacement for "net group 'name' /domain"

        .PARAMETER GroupName
        The group name to query for users. If not given, it defaults to "Domain Admins"

        .PARAMETER Domain
        The domain to query for group users.

        .PARAMETER FullData
        Switch. Returns full data objects instead of just group/users.

        .PARAMETER Recurse
        Switch. If the group member is a group, recursively try to query its members as well.

        .EXAMPLE
        > Get-NetGroup
        Returns the usernames that of members of the "Domain Admins" domain group.

        .EXAMPLE
        > Get-NetGroup -Domain testing -GroupName "Power Users"
        Returns the usernames that of members of the "Power Users" group
        in the 'testing' domain.

        .LINK
        http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]
        $GroupName = 'Domain Admins',

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [string]
        $Domain,

        [string]
        $PrimaryDC
    )

    process {

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
                if($PrimaryDC){
                    $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn")
                }
                else{
                    # otherwise try to connect to the DC for the target domain
                    $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
                }
                # samAccountType=805306368 indicates user objects
                $GroupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
            }
            catch{
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
            }
        }
        else{
            $Domain = (Get-NetDomain).Name

            # otherwise, use the current domain
            $GroupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
        }

        if ($GroupSearcher){
            $GroupSearcher.PageSize = 200
            $GroupSearcher.FindAll() | % {
                try{
                    $GroupFoundName = $_.properties.name[0]
                    $_.properties.member | ForEach-Object {
                        # for each user/member, do a quick adsi object grab
                        if ($PrimaryDC){
                            $properties = ([adsi]"LDAP://$PrimaryDC/$_").Properties
                        }
                        else {
                            $properties = ([adsi]"LDAP://$_").Properties
                        }

                        # check if the result is a user account- if not assume it's a group
                        if ($properties.samAccountType -ne "805306368"){
                            $isGroup = $True
                        }
                        else{
                            $isGroup = $False
                        }

                        $out = New-Object psobject
                        $out | add-member Noteproperty 'GroupDomain' $Domain
                        $out | Add-Member Noteproperty 'GroupName' $GroupFoundName

                        if ($FullData){
                            $properties.PropertyNames | % {
                                # TODO: errors on cross-domain users?
                                if ($_ -eq "objectsid"){
                                    # convert the SID to a string
                                    $out | Add-Member Noteproperty $_ ((New-Object System.Security.Principal.SecurityIdentifier($properties[$_][0],0)).Value)
                                }
                                elseif($_ -eq "objectguid"){
                                    # convert the GUID to a string
                                    $out | Add-Member Noteproperty $_ (New-Object Guid (,$properties[$_][0])).Guid
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
                        }
                        else {
                            $MemberDN = $properties.distinguishedName[0]
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                            if ($properties.samAccountType -ne "805306368"){
                                $isGroup = $True
                            }
                            else{
                                $isGroup = $False
                            }

                            if ($properties.samAccountName){
                                # forest users have the samAccountName set
                                $MemberName = $properties.samAccountName[0]
                            }
                            else {
                                # external trust users have a SID, so convert it
                                try {
                                    $MemberName = Convert-SidToName $properties.cn[0]
                                }
                                catch {
                                    # if there's a problem contacting the domain to resolve the SID
                                    $MemberName = $properties.cn
                                }
                            }
                            $out | add-member Noteproperty 'MemberDomain' $MemberDomain
                            $out | add-member Noteproperty 'MemberName' $MemberName
                            $out | add-member Noteproperty 'IsGroup' $IsGroup
                            $out | add-member Noteproperty 'MemberDN' $MemberDN
                        }

                        $out

                        if($Recurse) {
                            # if we're recursiving and  the returned value isn't a user account, assume it's a group
                            if($IsGroup){
                                if($FullData){
                                    Get-NetGroup -Domain $Domain -PrimaryDC $PrimaryDC -FullData -Recurse -GroupName $properties.SamAccountName[0]
                                }
                                else {
                                    Get-NetGroup -Domain $Domain -PrimaryDC $PrimaryDC -Recurse -GroupName $properties.SamAccountName[0]
                                }
                            }
                        }
                    }
                }
                catch {
                    write-verbose $_
                }
            }
        }
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


function Convert-SidToName {
    <#
    .SYNOPSIS
    Converts a security identifier (SID) to a group/user name.
    
    .PARAMETER SID
    The SID to convert.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $SID
    )

    process {
        try {
            $obj = (New-Object System.Security.Principal.SecurityIdentifier($SID))
            $obj.Translate( [System.Security.Principal.NTAccount]).Value
        }
        catch {
            Write-Warning "invalid SID"
        }
    }
}


function Translate-NT4Name {
    <#
    .SYNOPSIS
    Converts a user/group NT4 name (i.e. dev/john) to canonical format.
    Based on Bill Stewart's code from this article: 
        http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats

    .PARAMETER DomainObject
    The user/groupname to convert

    .PARAMETER DomainObject
    The user/groupname to convert

    .LINK
    http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
    #>
    [CmdletBinding()]
    param(
        [String] $DomainObject,
        [String] $Domain
    )

    if (-not $Domain) {
        $domain = (Get-NetDomain).name
    }

    $DomainObject = $DomainObject -replace "/","\"

    # Accessor functions to simplify calls to NameTranslate
    function Invoke-Method([__ComObject] $object, [String] $method, $parameters) {
        $output = $object.GetType().InvokeMember($method, "InvokeMethod", $NULL, $object, $parameters)
        if ( $output ) { $output }
    }
    function Set-Property([__ComObject] $object, [String] $property, $parameters) {
        [Void] $object.GetType().InvokeMember($property, "SetProperty", $NULL, $object, $parameters)
    }

    $Translate = new-object -comobject NameTranslate

    try {
        Invoke-Method $Translate "Init" (1, $Domain)
    }
    catch [System.Management.Automation.MethodInvocationException] { }

    Set-Property $Translate "ChaseReferral" (0x60)

    try {
        Invoke-Method $Translate "Set" (3, $DomainObject)
        (Invoke-Method $Translate "Get" (2))
    }
    catch [System.Management.Automation.MethodInvocationException] { }
}

function Get-NetLocalGroup {
    <#
        .SYNOPSIS
        Gets a list of all current users in a specified local group.

        .PARAMETER HostName
        The hostname or IP to query for local group users.

        .PARAMETER HostList
        List of hostnames/IPs to query for local group users.

        .PARAMETER GroupName
        The local group name to query for users. If not given, it defaults to "Administrators"

        .PARAMETER Recurse
        Switch. If the local member member is a domain group, recursively try to resolve its members to get a list of domain users who can access this machine.

        .EXAMPLE
        > Get-NetLocalGroup
        Returns the usernames that of members of localgroup "Administrators" on the local host.

        .EXAMPLE
        > Get-NetLocalGroup -HostName WINDOWSXP
        Returns all the local administrator accounts for WINDOWSXP

        .EXAMPLE
        > Get-NetLocalGroup -HostName WINDOWS7 -Resurse 
        Returns all effective local/domain users/groups that can access WINDOWS7 with
        local administrative privileges.

        .LINK
        http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
        http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $HostName = 'localhost',

        [string]
        $HostList,

        [string]
        $GroupName,

        [switch]
        $Recurse
    )

    process {

        $Servers = @()

        # if we have a host list passed, grab it
        if($HostList){
            if (Test-Path -Path $HostList){
                $Servers = Get-Content -Path $HostList
            }
            else{
                Write-Warning "[!] Input file '$HostList' doesn't exist!"
                $null
            }
        }
        else{
            # otherwise assume a single host name
            $Servers += $HostName
        }

        if (-not $GroupName){
            # resolve the SID for the local admin group - this should usually default to "Administrators"
            $objSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
            $GroupName = ($objgroup.Value).Split('\')[1]
        }

        # query the specified group using the WINNT provider, and
        # extract fields as appropriate from the results
        foreach($Server in $Servers)
        {
            try{
                $members = @($([ADSI]"WinNT://$server/$groupname").psbase.Invoke('Members'))
                $members | ForEach-Object {
                    $out = New-Object psobject
                    $out | Add-Member Noteproperty 'Server' $Server

                    $AdsPath = ($_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null)).Replace('WinNT://', '')

                    # try to translate the NT4 domain to a FQDN if possible
                    $name = Translate-NT4Name $AdsPath
                    if($name) {
                        $fqdn = $name.split("/")[0]
                        $objName = $AdsPath.split("/")[-1]
                        $name = "$fqdn/$objName"
                        $IsDomain = $True
                    }
                    else {
                        $name = $AdsPath
                        $IsDomain = $False
                    }

                    $out | Add-Member Noteproperty 'AccountName' $name

                    # translate the binary sid to a string
                    $out | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember('ObjectSID', 'GetProperty', $null, $_, $null),0)).Value)

                    # if the account is local, check if it's disabled, if it's domain, always print $false
                    # TODO: fix this error?
                    $out | Add-Member Noteproperty 'Disabled' $( if(-not $IsDomain) { try { $_.GetType().InvokeMember('AccountDisabled', 'GetProperty', $null, $_, $null) } catch { 'ERROR' } } else { $False } )

                    # check if the member is a group
                    $IsGroup = ($_.GetType().InvokeMember('Class', 'GetProperty', $Null, $_, $Null) -eq 'group')
                    $out | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $out | Add-Member Noteproperty 'IsDomain' $IsDomain
                    if($IsGroup){
                        $out | Add-Member Noteproperty 'LastLogin' ""
                    }
                    else{
                        try {
                            $out | Add-Member Noteproperty 'LastLogin' ( $_.GetType().InvokeMember('LastLogin', 'GetProperty', $null, $_, $null))
                        }
                        catch {
                            $out | Add-Member Noteproperty 'LastLogin' ""
                        }
                    }
                    $out

                    # if the result is a group domain object and we're recursing,
                    # try to resolve all the group member results
                    if($Recurse -and $IsDomain -and $IsGroup){
                        Write-Verbose "recurse!"
                        $FQDN = $name.split("/")[0]
                        $GroupName = $name.split("/")[1]
                        Get-NetGroup $GroupName -FullData -Recurse | % {
                            $out = New-Object psobject
                            $out | Add-Member Noteproperty 'Server' $name

                            $MemberDN = $_.distinguishedName
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                            if ($_.samAccountType -ne "805306368"){
                                $MemberIsGroup = $True
                            }
                            else{
                                $MemberIsGroup = $False
                            }

                            if ($_.samAccountName){
                                # forest users have the samAccountName set
                                $MemberName = $_.samAccountName
                            }
                            else {
                                # external trust users have a SID, so convert it
                                try {
                                    $MemberName = Convert-SidToName $_.cn
                                }
                                catch {
                                    # if there's a problem contacting the domain to resolve the SID
                                    $MemberName = $_.cn
                                }
                            }

                            $out | Add-Member Noteproperty 'AccountName' "$MemberDomain/$MemberName"
                            $out | Add-Member Noteproperty 'SID' $_.objectsid
                            $out | Add-Member Noteproperty 'Disabled' $False
                            $out | Add-Member Noteproperty 'IsGroup' $MemberIsGroup
                            $out | Add-Member Noteproperty 'IsDomain' $True
                            $out | Add-Member Noteproperty 'LastLogin' ''
                            $out
                        }
                    }
                }
            }
            catch {
                Write-Warning "[!] Error: $_"
            }
        }
    }
}

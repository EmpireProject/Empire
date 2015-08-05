function Invoke-FileSearch {
    <#
        .SYNOPSIS
        Searches a given server/path for files with specific terms in the name.

        .DESCRIPTION
        This function recursively searches a given UNC path for files with
        specific keywords in the name (default of pass, sensitive, secret, admin,
        login and unattend*.xml). The output can be piped out to a csv with the
        -OutFile flag. By default, hidden files/folders are included in search results.

        .PARAMETER Path
        UNC/local path to recursively search.

        .PARAMETER Terms
        Terms to search for.

        .PARAMETER OfficeDocs
        Search for office documents (*.doc*, *.xls*, *.ppt*)

        .PARAMETER FreshEXES
        Find .EXEs accessed within the last week.

        .PARAMETER AccessDateLimit
        Only return files with a LastAccessTime greater than this date value.

        .PARAMETER WriteDateLimit
        Only return files with a LastWriteTime greater than this date value.

        .PARAMETER CreateDateLimit
        Only return files with a CreationDate greater than this date value.

        .PARAMETER ExcludeFolders
        Exclude folders from the search results.

        .PARAMETER ExcludeHidden
        Exclude hidden files and folders from the search results.

        .PARAMETER CheckWriteAccess
        Only returns files the current user has write access to.

        .PARAMETER OutFile
        Output results to a specified csv output file.

        .OUTPUTS
        The full path, owner, lastaccess time, lastwrite time, and size for
        each found file.

        .EXAMPLE
        > Invoke-FileSearch -Path \\WINDOWS7\Users\
        Returns any files on the remote path \\WINDOWS7\Users\ that have 'pass',
        'sensitive', or 'secret' in the title.

        .EXAMPLE
        > Invoke-FileSearch -Path \\WINDOWS7\Users\ -Terms salaries,email -OutFile out.csv
        Returns any files on the remote path \\WINDOWS7\Users\ that have 'salaries'
        or 'email' in the title, and writes the results out to a csv file
        named 'out.csv'

        .EXAMPLE
        > Invoke-FileSearch -Path \\WINDOWS7\Users\ -AccessDateLimit 6/1/2014
        Returns all files accessed since 6/1/2014.

        .LINK
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $Path = '.\',

        [string[]]
        $Terms,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXES,

        [string]
        $AccessDateLimit = '1/1/1970',

        [string]
        $WriteDateLimit = '1/1/1970',

        [string]
        $CreateDateLimit = '1/1/1970',

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [string]
        $OutFile
    )

    begin {
        # default search terms
        $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config')

        # check if custom search terms were passed
        if ($Terms){
            if($Terms -isnot [system.array]){
                $Terms = @($Terms)
            }
            $SearchTerms = $Terms
        }

        # append wildcards to the front and back of all search terms
        for ($i = 0; $i -lt $SearchTerms.Count; $i++) {
            $SearchTerms[$i] = "*$($SearchTerms[$i])*"
        }

        # search just for office documents if specified
        if ($OfficeDocs){
            $SearchTerms = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }

        # find .exe's accessed within the last 7 days
        if($FreshEXES){
            # get an access time limit of 7 days ago
            $AccessDateLimit = (get-date).AddDays(-7).ToString('MM/dd/yyyy')
            $SearchTerms = '*.exe'
        }
    }

    process {
        # build our giant recursive search command w/ conditional options
        $cmd = "get-childitem $Path -rec $(if(-not $ExcludeHidden){`"-Force`"}) -ErrorAction SilentlyContinue -include $($SearchTerms -join `",`") | where{ $(if($ExcludeFolders){`"(-not `$_.PSIsContainer) -and`"}) (`$_.LastAccessTime -gt `"$AccessDateLimit`") -and (`$_.LastWriteTime -gt `"$WriteDateLimit`") -and (`$_.CreationTime -gt `"$CreateDateLimit`")} | select-object FullName,@{Name='Owner';Expression={(Get-Acl `$_.FullName).Owner}},LastAccessTime,LastWriteTime,Length $(if($CheckWriteAccess){`"| where { `$_.FullName } | where { Invoke-CheckWrite -Path `$_.FullName }`"}) $(if($OutFile){`"| export-csv -Append -notypeinformation -path $OutFile`"})"

        # execute the command
        Invoke-Expression $cmd
    }
}

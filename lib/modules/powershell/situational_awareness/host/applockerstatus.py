from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-AppLockerConfig',
            'Author': ['@matterpreter', 'Matt Hand'],
            'Description': ('This script is used to query the current AppLocker '
                            'policy on the target and check the status of a user-defined '
                            'executable or all executables in a path.'),
            'Background': False,
            'OutputExtension': None,
            'NeedsAdmin': False,
            'OpsecSafe': True,
            'Language': 'powershell',
            'MinLanguageVersion': '2',
            ]
        }

        self.options = {
            'Agent': {
                'Description':   'Agent to run module on.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'Executable': {
                'Description':   'Full filepath of executable or folder to check.',
                'Required'   :   True,
                'Value'      :   'c:\windows\system32\*.exe'
            },
            'User': {
                'Description':   'Username to test the execution policy for.',
                'Required'   :   False,
                'Value'      :   'Everyone'
            }
        }

        self.mainMenu = mainMenu

        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/host/Get-AppLockerConfig.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script

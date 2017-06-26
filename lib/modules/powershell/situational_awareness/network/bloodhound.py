from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-BloodHound',

            'Author': ['@harmj0y', '@_wald0', '@cptjesus'],

            'Description': ('Execute BloodHound data collection.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://bit.ly/getbloodhound'
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
            'Domain' : {
                'Description'   :   'The domain to use for the query, defaults to the current domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DomainController' : {
                'Description'   :   'Domain controller to reflect LDAP queries through.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CollectionMethod' : {
                'Description'   :   "The method to collect data. 'Group', 'LocalGroup', 'GPOLocalGroup', 'Sesssion', 'LoggedOn', 'Trusts, 'Stealth', or 'Default'.",
                'Required'      :   True,
                'Value'         :   'Default'
            },
            'SearchForest' : {
                'Description'   :   'Switch. Search all domains in the forest.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CSVFolder' : {
                'Description'   :   'The CSV folder to use for output, defaults to the current folder location.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CSVPrefix' : {
                'Description'   :   'A prefix for all CSV files.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'GlobalCatalog' : {
                'Description'   :   'The global catalog location to resolve user memberships from.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Threads' : {
                'Description'   :   'The maximum concurrent threads to execute.',
                'Required'      :   True,
                'Value'         :   '20'
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
        
        moduleName = self.info["Name"]

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/BloodHound.ps1"

        # TODO: just CSV output for this bloodhound version? no output to file?

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = "%s\n%s" %(moduleCode, moduleName)

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 

        script += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'

        return script


from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-MapDomainTrusts',

            'Author': ['@harmj0y'],

            'Description': ('Maps all reachable domain trusts with .CSV output. Part of PowerView.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView'
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
            'LDAP' : {
                'Description'   :   'Switch. Use LDAP for domain queries (less accurate).',
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Invoke-MapDomainTrusts.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        if self.options['LDAP']['Value'].lower() == "true":
            script += "Invoke-MapDomainTrustsLDAP | ConvertTo-Csv -NoTypeInformation"
            script += '| Out-String | %{$_ + \"`n\"};"`nInvoke-MapDomainTrustsLDAP completed"'
        else:
            script += "Invoke-MapDomainTrusts | ConvertTo-Csv -NoTypeInformation"
            script += '| Out-String | %{$_ + \"`n\"};"`nInvoke-MapDomainTrusts completed"'

        return script

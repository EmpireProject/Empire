from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-SQLServerInfo',
            'Author': ['@_nullbind', '@0xbadjuju'],
            'Description': ('Returns basic server and user information from target SQL Servers.'),
            'Background' : True,
            'OutputExtension' : None,
			
            'NeedsAdmin' : False,
            'OpsecSafe' : True,
            'Language' : 'powershell',
			'MinPSVersion' : '2',
            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1'
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
            'Username' : {
                'Description'   :   'SQL Server or domain account to authenticate with.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'SQL Server or domain account password to authenticate with.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Instance' : {
                'Description'   :   'SQL Server instance to connection to.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CheckAll' : {
                'Description'   :   'Check all systems retrieved by Get-SQLInstanceDomain',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        self.mainMenu = mainMenu
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self):
        username = self.options['Username']['Value']
        password = self.options['Password']['Value']
        instance = self.options['Instance']['Value']
        check_all = self.options['CheckAll']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Get-SQLServerInfo.ps1"
        script = ""
        try:
            with open(moduleSource, 'r') as source:
                script = source.read()
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""
        
        if check_all:
            auxModuleSource = self.mainMenu.installPath + "data/module_source/situational_awareness/network/Get-SQLInstanceDomain.ps1"
            try:
                with open(auxModuleSource, 'r') as auxSource:
                    auxScript = auxSource.read()
                    script += " " + auxScript
            except:
                print helpers.color("[!] Could not read additional module source path at: " + str(auxModuleSource))
            script += " Get-SQLInstanceDomain "
            if username != "":
                script += " -Username "+username
            if password != "":
                script += " -Password "+password
            script += " | "
        script += " Get-SQLServerInfo"
        if username != "":
            script += " -Username "+username
        if password != "":
            script += " -Password "+password
        if instance != "" and not check_all:
            script += " -Instance "+instance

        return script

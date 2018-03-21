from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-SubnetRanges',

            'Author': ['@benichmt1'],

            'Description': ('Pulls hostnames from AD, performs a Reverse DNS lookup, and parses the output into ranges.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'Uses Powerview to query AD computers'
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


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        moduleName = self.info["Name"]
        
        # read in the common powerview.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/powerview.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        # get just the code needed for the specified function
        script = helpers.strip_powershell_comments(moduleCode)

        script += 
        """
        $Servers = Get-DomainComputer"""
        
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 
        script += """| ForEach-Object {try{Resolve-DNSName $_.dnshostname -Type A -errorAction SilentlyContinue}catch{Write-Warning 'Computer Offline or Not Responding'} } | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue; 
        $count = 0; $subarry =@(); 
        foreach($i in $Servers){$IPByte = $i.Split("."); 
        $subarry += $IPByte[0..2] -join"."} $final = $subarry | group;
        Write-Output{"The following subnetworks were discovered:"}; $final | ForEach-Object {Write-Host "$($_.Name).0/24" - "$($_.Count) Hosts"} 
        """

        script += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
return script

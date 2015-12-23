from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Enumerate-TrustedDocuments',

            # list of one or more authors for the module
            'Author': ['@jamcut'],

            # more verbose multi-line description of the module
            'Description': ('This module will enumerate the appropriate registry '
                            'keys to determine what, if any, trusted documents '
                            'exist on the host.  It will also identify trusted document locations.'
                            ),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,
            
            # The minimum PowerShell version needed for the module to run
            'MinPSVersion' : '2',

            # list of any references/other comments
            'Comments': [
                'comment',
                'http://link/'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to enumerate trusted documents from.',
                'Required'      :   True,
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


    def generate(self):
        
        # the PowerShell script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.   

#         script = """
# function Enumerate-TrustedDocuments{

# $BASE_EXCEL_REG_LOCATIONS = "HKCU:\Software\Microsoft\Office\11.0\Excel\Security\Trusted Documents", "HKCU:\Software\Microsoft\Office\12.0\Excel\Security\Trusted Documents", "HKCU:\Software\Microsoft\Office\14.0\Excel\Security\Trusted Documents", "HKCU:\Software\Microsoft\Office\15.0\Excel\Security\Trusted Documents" 
# $valid_excel_reg_locations = @()
# $trusted_excel_documents = @()
# foreach ($location in $BASE_EXCEL_REG_LOCATIONS){
#     $valid_path = Test-Path $location
#     if ($valid_path -eq $True){
#         $valid_excel_reg_locations += $location
#     }
# }
# if ($valid_excel_reg_locations.length -eq 0){
#     Write-Output "No trusted document locations found"
# }
# else {
#     Write-Output "Trusted locations:"
#     foreach ($valid_location in $valid_excel_reg_locations){
#         $valid_location = $valid_location -join "`n"
#         Write-Output $valid_location
#     }
# }
# foreach ($valid_location in $valid_excel_reg_locations){
#     $valid_location = $valid_location -join "\TrustRecords"
#     if ((Test-Path $valid_location) -eq $True){
#         $trusted_document_property = Get-ChildItem $valid_location | select Property
#         $trusted_document = $trusted_document_property.property
#         $trusted_excel_documents += $trusted_document
#     }
# }
# if ($trusted_excel_documents.length -eq 0){
#     Write-Output "No trusted documents found"
# }
# else{
#     Write-Output "Trusted documents:"
#     foreach ($trusted_document in $trusted_excel_documents){
#         $trusted_document = $trusted_document -join "`n"
#         Write-Output $trusted_document
# }
# }
# }
# Enumerate-TrustedDocuments"""


        # # if you're reading in a large, external script that might be updates,
        # #   use the pattern below
        # # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/host/Enumerate-TrustedDocuments.ps1"
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode
        script += "Enumerate-TrustedDocuments -ToString"


        # # add any arguments to the end execution of the script
        # for option,values in self.options.iteritems():
        #     if option.lower() != "agent":
        #         if values['Value'] and values['Value'] != '':
        #             if values['Value'].lower() == "true":
        #                 # if we're just adding a switch
        #                 script += " -" + str(option)
        #             else:
        #                 script += " -" + str(option) + " " + str(values['Value'])

        return script

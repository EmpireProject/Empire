"""
Server class for Empire. Allows multiple users to connect to a single empire instance.
"""

from pydispatch import dispatcher

# Empire imports
import empire
import helpers
import messages
import agents
import listeners
import modules
import stagers
import credentials
import plugins
import users
from events import log_event
from zlib_wrapper import compress
from zlib_wrapper import decompress

# server imports
import sys
import sqlite3
import os
import hashlib
import time
import fnmatch
import shlex
import marshal
import pkgutil
import importlib
import base64
import threading
import json
import StringIO
import copy
from flask_socketio import SocketIO, join_room, leave_room, disconnect, send, emit
from flask import Flask, request


class MainMenu():
    """
    The MainMenu class for the server is responsible for maintaining client connections and managing empire
    """

    def __init__(self, args=None):
        
        # Set up the event handling system
        dispatcher.connect(self.handle_event, sender=dispatcher.Any)

        # globalOptions[optionName] = (value, required, description)

        self.globalOptions = {}

        # plugins

        self.loadedPlugins = {}

        # Agent results cache/buffer
        self.historyBuffer = {}

        # empty database object
        self.conn = self.database_connect()
        time.sleep(1)

        self.app = Flask(__name__)

        self.socketio = SocketIO(self.app)

        self.lock = threading.Lock() 
        (self.isroot, self.installPath, self.ipWhiteList, self.ipBlackList, self.obfuscate, self.obfuscateCommand) = helpers.get_config('rootuser, install_path,ip_whitelist,ip_blacklist,obfuscate,obfuscate_command')

        self.args = args 
        # instantiate the agents, listeners, and stagers objects
        self.agents = agents.Agents(self, args=args)
        self.credentials = credentials.Credentials(self, args=args)
        self.stagers = stagers.Stagers(self, args=args)
        self.modules = modules.Modules(self, args=args)
        self.listeners = listeners.Listeners(self, args=args)
        self.users = users.Users(self, args=args)
        self.resourceQueue = []
        #A hashtable of autruns based on agent language
        self.autoRuns = {}

        # print the loading menu
        messages.loading()

    def get_db_connection(self):
        """
        Returns the 
        """
        self.lock.acquire()
        self.conn.row_factory = None
        self.lock.release()
        return self.conn

    def handle_event(self, signal, sender):
        """
        Whenever an event is received from the dispatcher, log it to the DB,
        decide whether it should be printed, and if so, print it.
        If self.args.debug, also log all events to a file
        """

        # load up the signal so we can inspect it
        try:
            signal_data = json.loads(signal)
        except ValueError:
            print(helpers.color("[!] Error: bad signal recieved {} from sender {}".format(signal, sender)))
            return

        # this should probably be set in the event itself but we can check
        # here (and for most the time difference won't matter so it's fine)
        if 'timestamp' not in signal_data:
            signal_data['timestamp'] = helpers.get_datetime()

        # if this is related to a task, set task_id; this is its own column in
        # the DB (else the column will be set to None/null)
        task_id = None
        if 'task_id' in signal_data:
            task_id = signal_data['task_id']

        event_data = json.dumps({'signal': signal_data, 'sender': sender})

        # emit any signal that should be printed

        if "agents" in sender:
            
            agentName = sender.split('/')[-1]

            if "[+] Initial agent" in signal:
                emit('Agents', {'Result':signal_data['message']})
                # create a new results buffer object whenever a new agent checks in
                self.historyBuffer[agentName] = StringIO.StringIO()
            
            elif "returned results" in signal:
                results = self.agents.get_agent_results_db(agentName)
                if results:
                    send({'Agents':results}, room=agentName)

                # check to make sure the size of the agent results will not exceed the limit when added to the buffer
                if (self.historyBuffer[agentName].len + len(results)) <= 512000:
                    self.historyBuffer[agentName].write(results)
                else:
                    self.historyBuffer[agentName] = StringIO.StringIO()
                    self.historyBuffer[agentName].write(results)
            
            elif ("[+] Listener for" in signal) and ("updated to" in signal):
                send({'Listeners': signal_data['message']})

            elif "[!] Agent" in signal and "exiting" in signal:
                send({'Agents': signal_data['message']})

            elif "WARNING" in signal or "attempted overwrite" in signal:
                send({'Empire': signal_data['message']})

            elif "on the blacklist" in signal:
                send({'Empire':signal_data['message']})

        elif "EmpireServer" in sender:
            if "[!] Error starting listener" in signal:
                send({'Empire':signal_data['message']})

        elif "Listeners" in sender:
            send({'Empire':signal_data['message']})

        elif "Users" in sender:
            send({'Users':signal_data['message']})


    def database_connect(self):
        """
        Connect to the default database at ./data/empire.db.
        """
        try:
            # set the database connectiont to autocommit w/ isolation level
            self.conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
            self.conn.text_factory = str
            self.conn.isolation_level = None
            return self.conn

        except Exception:
            print helpers.color("[!] Could not connect to database")
            print helpers.color("[!] Please run database_setup.py")
            sys.exit()

    
    def start_server(self):
        """
        Start the Empire team server
        """

        ####################################################################
        #    socketIO Server guide:
        #       
        #    - Any client may connect to the server but all custom events require authentication.
        #    - Clients can emit the 'login' custom event to do so. The data should be json (serialized) and include both a username and password field.
        #    - Once the disconnect event occurs on the user is removed from the users table
        #
        #   
        #    - There are custom events for each menu/class per se:
        #    - listeners, modules, agents, stagers
        #    - Data sent from the client for any custom event should be in the following json format
        #    * - required arguments
        #
        #   Event - listeners
        #         - Action: VIEW, KILL, OPTIONS, EXECUTE
        #         - Arguments _____________
        #           -VIEW    --- Name
        #           -KILL    --- Name*
        #           -OPTIONS --- Type*
        #           -EXECUTE --- Type*,Options
        #
        #   Event - modules
        #         - Action: VIEW, EXECUTE
        #         - Arguments: arguments can vary per action, per event.
        #   
        #   Event - agents
        #         - Action: VIEW, KILL, INTERACT, EXECUTE, RETURN
        #         - Arguments ______________
        #           - VIEW   --- Name
        #           - KILL   --- Name*
        #           - INTERACT --- Name*
        #           - EXECUTE --- Name*,Command*
        #           - RETURN --- Name*
        #
        #
        #   Event - stagers
        #         - Action: VIEW, EXECUTE
        #         - Arguments: _______________
        #           - VIEW --- stager_name 
        #           - EXECUTE --- stager_name*,Listener*
        ####################################################################

        app = Flask(__name__)
        socketio = SocketIO(app)


        @socketio.on('login')
        def handle_login(data):
            """
            Authenticate clients. Should be called before anything else, after connecting
            """
            if data['username'] and data['password']:
                if self.users.authenticate_user(request.sid, data['username'], data['password']):
                    emit('user_login', {"Result":"Logon success"})
                else:
                    emit('user_login', {"Result":"Logon failure"})
            else:
                emit('user_login',{"Result":"missing username and/or password"})


        @socketio.on('connect')
        def handle_connect():
            """
            Handle when new clients connect. Authentication is not required here. Only when accessing any of the custom events
            """
            signal = json.dumps({
                'print': False,
                'message':"New client session started with sid: {}".format(request.sid)
            })
            dispatcher.send(signal, sender="EmpireServer")
            emit('new_session', {"message": "Session initiated"})

        @socketio.on('disconnect')
        def handle_disconnect():
            """
            Handle when a client disconnects
            """
            self.users.remove_user(request.sid)
            emit('message', {"message": "Session closed"})

        @socketio.on('stagers')
        def handle_stagers_event(data):
            """
            Handles all client messages for the 'stagers' event
            """

            if self.users.is_authenticated(request.sid):
                stagers = ""
                if data['Action'] and data['Action'] == 'VIEW':
                    if data['Arguments'] and data['Arguments']['stager_name'] == '':
                        stagers = []
                        for stagerName, stager in self.stagers.stagers.iteritems():
                            info = copy.deepcopy(stager.info)
                            info['options'] = stager.options
                            info['Name'] = stagerName
                            stagers.append(info)
                    elif data['Arguments'] and data['Arguments']['stager_name'] != '':
                        stager_name = data['Arguments']['stager_name']
                        stagers = []
                        if stager_name not in self.stagers.stagers:
                            stagers.append("{} is not a valid stager name".format(stager_name))
                        else:
                            for stagerName, stager in self.stagers.stagers.iteritems():
                                if stagerName == stager_name:
                                    info = copy.deepcopy(stager.info)
                                    info['options'] = stager.options
                                    info['Name'] = stagerName
                                    stagers.append(info)



                    send({"Result": stagers})

                elif data['Action'] and data['Action'] == 'EXECUTE':
                    if data['Arguments'] and data['Arguments']['stager_name'] != '' and data['Arguments']['Listener'] != '':
                        stager_name = data['Arguments']['stager_name']
                        listener = data['Arguments']['Listener']
                        stagers = []
                        if stager_name not in self.stagers.stagers:
                            stagers.append("{} is not a valid stager name".format(stager_name))
                        else:
                            stager = self.stagers.stagers[stager_name]
                            # set all passed options
                            for option, values in data['Arguments'].iteritems():
                                if option != 'StagerName':
                                    if option not in stager.options:
                                        send({'Result': 'Invalid option {}, check capitalization.'.format(option)
                                    stager.options[option]['Value'] = values
                            
                            # validate stager options
                            for option, values in stager.options.iteritems():
                                if values['Required'] and ((not values['Value']) or (values['Value'] == '')):
                                    send({'Result': 'required stager options missing'})

                            stagerOut = copy.deepcopy(stager.options)

                            if ('OutFile' in stagerOut) and (stagerOut['OutFile']['Value'] != ''):
                                # if the output was intended for a file, return the base64 encoded text
                                stagerOut['Output'] = base64.b64encode(stager.generate())
                                stagers.append(stagerOut)
                            else:
                                # otherwise return the text of the stager generation
                                stagerOut['Output'] = stager.generate()
                                stagers.append(stagerOut)
                            
                            send({'Result':stagers})

                    else:
                        send({'Result':'Missing required argument'})
                            

            else:
                send({"Result": "Unauthenticated"})
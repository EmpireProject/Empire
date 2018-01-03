#!/usr/bin/python

import requests, sys, os, json


baseurl = "http://localhost:1337"
endpoint = "/api/admin/login"
headers = {"Content-Type":"application/json"}


# Authentication Test

data = {"username":"empireadmin", "password":"Password123!"} 

jdata = json.dumps(data)

resp = requests.get(baseurl+endpoint, data=jdata)
#!/bin/bash

apt-get install python-pip

#ubuntu 14.04 LTS dependencies
apt-get install python-dev
apt-get install python-m2crypto
apt-get install swig
pip install pycrypto

#kali dependencies
pip install iptools
pip install pydispatcher

./setup_database.py

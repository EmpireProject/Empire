#!/bin/bash

apt-get install python-pip

#kali dependencies
pip install iptools
pip install pydispatcher

./setup_database.py

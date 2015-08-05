#!/bin/bash

apt-get install python-pip

pip install iptools
pip install pydispatcher

./setup_database.py

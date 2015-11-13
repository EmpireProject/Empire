#!/bin/bash

version=$( lsb_release -r | grep -oP "[0-9]+" | head -1 )
if lsb_release -d | grep -q "Fedora"; then
	Release=Fedora
	dnf install -y python-devel m2crypto python-m2ext swig python-iptools python3-iptools 
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
elif lsb_release -d | grep -q "Kali"; then
	Release=Kali
	apt-get install python-dev
	apt-get install python-m2crypto
	apt-get install swig
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
elif lsb_release -d | grep -q "Ubuntu"; then
	Release=Ubuntu
	apt-get install python-dev
	apt-get install python-m2crypto
	apt-get install swig
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
else
	echo "Unknown distro - Debian/Ubuntu Fallback"
	 apt-get install python-dev
	 apt-get install python-m2crypto
	 apt-get install swig
	 pip install pycrypto
	 pip install iptools
	 pip install pydispatcher
fi

./setup_database.py

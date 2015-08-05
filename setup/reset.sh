#!/bin/bash

# reset the database
rm ../data/empire.db
./setup_database.py
cd ..

# remove the debug file if it exists
rm empire.debug

# remove the download folders
rm -rf ./downloads/

# start up Empire in debug mode
./empire --debug

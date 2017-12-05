#!/usr/bin/env bash
set -ex
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=empireproject
# image name
IMAGE=empire
docker build -t $USERNAME/$IMAGE:latest .

#!/usr/bin/env bash
set -ex

# SET THE FOLLOWING VARIABLES
USERNAME=empireproject
IMAGE=empire
VERSION="$(curl -s https://raw.githubusercontent.com/EmpireProject/Empire/master/lib/common/empire.py | grep "VERSION =" | cut -d '"' -f2)"

# UPDATE THE SOURCE CODE
git pull

# ALERT VERSION
echo "Building Version: $VERSION"

# START BUILD
./.build.sh

# DOCKER TAG/VERSIONING
docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$VERSION

# PUSH TO DOCKER HUB
docker push $USERNAME/$IMAGE:latest
echo "Docker image pushed: $USERNAME/$IMAGE:latest"
docker push $USERNAME/$IMAGE:$VERSION
echo "Docker image pushed: $USERNAME/$IMAGE:$VERSION"

# NOTE: Only use this when you want to build image locally
#       else use `docker pull empireproject\empire:{VERSION}`
#       all image versions can be found at: https://hub.docker.com/r/empireproject/empire/

# -----BUILD COMMANDS----
# 1) build command: `docker build -t empireproject/empire .`
# 2) create volume storage: `docker create -v /opt/Empire --name data empireproject/empire`
# 3) run out container: `docker run -ti --volumes-from data empireproject/empire /bin/bash`

# -----RELEASE COMMANDS----
# 1) `USERNAME=empireproject`
# 2) `IMAGE=empire`
# 3) `git pull`
# 4) `export VERSION="$(curl -s https://raw.githubusercontent.com/EmpireProject/Empire/master/lib/common/empire.py | grep "VERSION =" | cut -d '"' -f2)"`
# 5) `docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$VERSION`
# 1) `docker push $USERNAME/$IMAGE:latest`
# 2) `docker push $USERNAME/$IMAGE:$VERSION`

# -----BUILD ENTRY-----

# image base
FROM ubuntu:16.04

# author
MAINTAINER Killswitch-GUI

# extra metadata
LABEL version="1.0"
LABEL description="Dockerfile base for Empire server."

# expose ports for Empire C2 listerners
# EXPOSE 80,443

# update repo sources
RUN apt-get clean
RUN apt-get update

# build depends
RUN apt-get install -qy apt-utils
RUN apt-get install -qy git
RUN apt-get install -qy wget
RUN apt-get install -qy curl
RUN apt-get install -qy sudo
RUN apt-get install -qy lsb-core
RUN apt-get install -qy python2.7
RUN apt-get install -qy python-pip

# cleanup image
RUN apt-get -qy autoremove

# build empire
RUN git clone https://github.com/EmpireProject/Empire.git /opt/Empire
ENV STAGING_KEY=RANDOM
RUN cd /opt/Empire/setup/ && ./install.sh

# -----END OF BUILD-----





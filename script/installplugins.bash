#!/bin/bash
docker cp plugins.bash jenkins:var/jenkins_home && \
docker container exec jenkins bash -c "bash var/jenkins_home/plugins.bash
exec bash

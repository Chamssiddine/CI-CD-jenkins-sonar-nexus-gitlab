#!/bin/bash
echo 'All Containers with their respective IP@'
docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -aq)
exec bash
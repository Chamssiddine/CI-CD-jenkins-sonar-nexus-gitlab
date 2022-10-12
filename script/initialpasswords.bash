#!/bin/bash
echo 'Jenkins admin password \'
docker container exec jenkins sh -c "cat /var/jenkins_home/secrets/initialAdminPassowrd"
echo '\ Nexus admin password \'
docker container exec nexus bash -c "cat /nexus-data/admin.password "
echo '\ Gitlab root password'
docker exec -it gitlab grep 'Password:' /etc/gitlab/initial_root_password
exec bash
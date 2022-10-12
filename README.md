# DevOps-First-Project
the project aime to create a CI/CD platform hosted on container using docker compose where we clone our source code which is
generated by JHipster from Gitlab server Hosted on our machine, we pass the code through quality Gates using SonarQube
afterward we Build and test the application using NPM for the front end and Maven for back-end afterward we Dockerize the
application and create our docker image finally we push the artifact and docker image to Nexus Repository for Version Control
and if our application is ready we deploy it and launch it inside docker container using docker-compose file.


![Plot](img/pipeline.png)

### Purpose:
we will be using 
- gitlab
- jenkins
- Maven
- Docker & Docker-compose
- SonarQube
- Nexus Sonatype
- Jhipster

### Walkthrough

Launch all the container with docker-compose.

Configure Jenkins, Gitlab, SonarQube, NexusSonatype.

Create Jenkinsfile which container the stages of our pipeline.

Create Triggers.

Test the whole CI/CD pipeline.

### Launch the Containers

Clone the repo, and go to docker-compose folder and type

 $ sudo docker-compose up -d 

to view the logs don't use the tag -d and don't close the terminal or the containers will be terminating

### Configuration

- To get all the initial passwords go to the script folder and type 

 $ bash initialpasswords.bash

NOTE: After 24 hours the passwords will be gone so you can store them somewhere.

- You can install the plugins in jenkins using the script by going to script folder and type

 $ bash installplugins.bash

// if there is a problem with installing some plugins let me know and you can install it manually in jenkins

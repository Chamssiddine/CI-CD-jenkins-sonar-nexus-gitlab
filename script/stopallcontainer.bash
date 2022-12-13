#!/bin/bash
sudo docker stop $(sudo docker ps -q)
exec bash


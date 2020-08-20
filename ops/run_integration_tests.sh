#!/bin/bash

docker-compose -f ./ops/docker-compose.yml build --no-cache vault
docker-compose -f ./ops/docker-compose.yml up -d
TAGS=integration ./ops/run_local_tests.sh
docker-compose -f ./ops/docker-compose.yml down

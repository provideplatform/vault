#!/bin/bash

docker-compose -f ./ops/docker-compose-integration.yml build --no-cache vault
docker-compose -f ./ops/docker-compose-integration.yml up -d
TAGS=integration ./ops/run_local_tests_long.sh
docker-compose -f ./ops/docker-compose.yml logs
docker-compose -f ./ops/docker-compose-integration.yml down
docker volume rm ops_provide-db

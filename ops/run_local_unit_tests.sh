#!/bin/bash

docker-compose -f ./ops/docker-compose-db.yml up -d
TAGS=unit ./ops/run_local_tests.sh
docker-compose -f ./ops/docker-compose-db.yml down
docker volume rm ops_vault-db
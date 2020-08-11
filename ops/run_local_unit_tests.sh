#!/bin/bash

docker-compose -f ./ops/docker-compose-db.yml up -d
	rm -rf ./.bin/vault_migrate 2>/dev/null || true
	go build -v -o ./.bin/vault_migrate ./cmd/migrate
	./ops/migrate_local.sh
TAGS=unit ./ops/run_local_tests.sh
docker-compose -f ./ops/docker-compose-db.yml down
docker volume rm ops_vault-db
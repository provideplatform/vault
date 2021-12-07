.PHONY: build clean ecs_deploy install integration lint migrate mod run_api run_consumer run_local run_local_dependencies stop_local_dependencies stop_local test

clean:
	rm -rf ./.bin 2>/dev/null || true
	rm ./vault 2>/dev/null || true
	go fix ./...
	go clean -i ./...

build: clean mod
	go fmt ./...
	CGO_ENABLED=0 go build -v -o ./.bin/vault_api ./cmd/api
	CGO_ENABLED=0 go build -v -o ./.bin/vault_consumer ./cmd/consumer
	CGO_ENABLED=0 go build -v -o ./.bin/vault_migrate ./cmd/migrate

ecs_deploy:
	./ops/ecs_deploy.sh

install: clean
	go install ./...

lint:
	./ops/lint.sh

migrate: mod
	rm -rf ./.bin/vault_migrate 2>/dev/null || true
	go build -v -o ./.bin/vault_migrate ./cmd/migrate
	./ops/migrate.sh

mod:
	go mod init 2>/dev/null || true
	go mod tidy
	go mod vendor 

run_api: build run_local_dependencies
	./ops/run_api.sh

run_consumer: build run_consumer
	./ops/run_consumer.sh

run_local: build run_local_dependencies
	./ops/run_local.sh

run_local_dependencies:
	./ops/run_local_dependencies.sh

stop_local_dependencies:
	./ops/stop_local_dependencies.sh

stop_local:
	./ops/stop_local.sh

test: build
	./ops/run_local_unit_tests.sh

test_local: build
	./ops/run_local_unit_tests.sh

integration:
	./ops/run_integration_tests.sh

debug:
	./ops/run_debug.sh

stop_debug:
	./ops/stop_debug.sh

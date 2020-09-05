#!/bin/bash

if [[ -z "${LOG_LEVEL}" ]]; then
  LOG_LEVEL=info
fi

if [[ -z "${DATABASE_HOST}" ]]; then
  DATABASE_HOST=localhost
fi

if [[ -z "${DATABASE_NAME}" ]]; then
  DATABASE_NAME=vault_test
fi

if [[ -z "${DATABASE_PORT}" ]]; then
  DATABASE_PORT=5432
fi

if [[ -z "${DATABASE_USER}" ]]; then
  DATABASE_USER=vaulttest
fi

if [[ -z "${DATABASE_PASSWORD}" ]]; then
  DATABASE_PASSWORD=vaulttest
fi

if [[ -z "${DATABASE_SUPERUSER}" ]]; then
  DATABASE_SUPERUSER=prvd
fi

if [[ -z "${DATABASE_SUPERUSER_PASSWORD}" ]]; then
  DATABASE_SUPERUSER_PASSWORD=prvdp455
fi

if [[ -z "${DATABASE_SSL_MODE}" ]]; then
  DATABASE_SSL_MODE=disable
fi

if [[ -z "${DATABASE_LOGGING}" ]]; then
  DATABASE_LOGGING=false
fi

./ops/await_tcp.sh ${DATABASE_HOST}:${DATABASE_PORT}

DATABASE_HOST=$DATABASE_HOST \
DATABASE_PORT=$DATABASE_PORT \
DATABASE_NAME=$DATABASE_NAME \
DATABASE_USER=$DATABASE_USER \
DATABASE_PASSWORD=$DATABASE_PASSWORD \
DATABASE_LOGGING=$DATABASE_LOGGING \
DATABASE_SSL_MODE=$DATABASE_SSL_MODE \
DATABASE_SUPERUSER=$DATABASE_SUPERUSER \
DATABASE_SUPERUSER_PASSWORD=$DATABASE_SUPERUSER_PASSWORD \
LOG_LEVEL=$LOG_LEVEL \
echo "database name..."
echo $DATABASE_NAME
./.bin/vault_migrate
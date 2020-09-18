#!/bin/bash

docker-compose -f ./ops/docker-compose-db.yml up -d

set -e
echo "" > coverage.txt 

if [[ -z "${DATABASE_NAME}" ]]; then
  DATABASE_NAME=vault_dev
fi

if [[ -z "${DATABASE_USER}" ]]; then
  DATABASE_USER=vault
fi

if [[ -z "${DATABASE_PASSWORD}" ]]; then
  DATABASE_PASSWORD=vault
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
  DATABASE_LOGGING=true
fi

if [[ -z "${DATABASE_PORT}" ]]; then
  DATABASE_PORT=5432
fi

if [[ -z "${TAGS}" ]]; then
  TAGS=unit
fi

if [[ -z "${RACE}" ]]; then
  RACE=true
fi

if [[ -z "${VAULT_USK_VALIDATION_HASH}" ]]; then
  VAULT_USK_VALIDATION_HASH=aa5ef33a968701d06efa0ef5dafb6ba4789a31a7d1c2c259cc3f7f8dbe05c004174720d1b0aa57681bbb889d5199e51ef6ca4afcf5886682db2dfee713d69a8c
fi

PGPASSWORD=$DATABASE_SUPERUSER_PASSWORD dropdb -U $DATABASE_SUPERUSER -h 0.0.0.0 -p $DATABASE_PORT $DATABASE_NAME || true >/dev/null
PGPASSWORD=$DATABASE_SUPERUSER_PASSWORD dropuser -U $DATABASE_SUPERUSER -h 0.0.0.0 -p $DATABASE_PORT $DATABASE_USER || true >/dev/null

DATABASE_HOST=$DATABASE_HOST \
DATABASE_PORT=$DATABASE_PORT \
DATABASE_USER=$DATABASE_USER \
DATABASE_PASSWORD=$DATABASE_PASSWORD \
DATABASE_NAME=$DATABASE_NAME \
DATABASE_SUPERUSER=$DATABASE_SUPERUSER \
DATABASE_SUPERUSER_PASSWORD=$DATABASE_SUPERUSER_PASSWORD \
echo here we are
echo $VAULT_USK_VALIDATION_HASH
VAULT_USK_VALIDATION_HASH=$VAULT_USK_VALIDATION_HASH \

echo "database name:" $DATABASE_NAME
./.bin/vault_migrate


JWT_SIGNER_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAullT/WoZnxecxKwQFlwE
9lpQrekSD+txCgtb9T3JvvX/YkZTYkerf0rssQtrwkBlDQtm2cB5mHlRt4lRDKQy
EA2qNJGM1Yu379abVObQ9ZXI2q7jTBZzL/Yl9AgUKlDIAXYFVfJ8XWVTi0l32Vsx
tJSd97hiRXO+RqQu5UEr3jJ5tL73iNLp5BitRBwa4KbDCbicWKfSH5hK5DM75EyM
R/SzR3oCLPFNLs+fyc7zH98S1atglbelkZsMk/mSIKJJl1fZFVCUxA+8CaPiKbpD
QLpzydqyrk/y275aSU/tFHidoewvtWorNyFWRnefoWOsJFlfq1crgMu2YHTMBVtU
SJ+4MS5D9fuk0queOqsVUgT7BVRSFHgDH7IpBZ8s9WRrpE6XOE+feTUyyWMjkVgn
gLm5RSbHpB8Wt/Wssy3VMPV3T5uojPvX+ITmf1utz0y41gU+iZ/YFKeNN8WysLxX
AP3Bbgo+zNLfpcrH1Y27WGBWPtHtzqiafhdfX6LQ3/zXXlNuruagjUohXaMltH+S
K8zK4j7n+BYl+7y1dzOQw4CadsDi5whgNcg2QUxuTlW+TQ5VBvdUl9wpTSygD88H
xH2b0OBcVjYsgRnQ9OZpQ+kIPaFhaWChnfEArCmhrOEgOnhfkr6YGDHFenfT3/RA
PUl1cxrvY7BHh4obNa6Bf8ECAwEAAQ==
-----END PUBLIC KEY-----'

# validation hash for test unsealerkey 53534144444f374f4c544849564a5146465950434c353645454a344856594134
VAULT_USK_VALIDATION_HASH='aa5ef33a968701d06efa0ef5dafb6ba4789a31a7d1c2c259cc3f7f8dbe05c004174720d1b0aa57681bbb889d5199e51ef6ca4afcf5886682db2dfee713d69a8c'

pkgs=(test)
for d in "${pkgs[@]}" ; do
  pkg=$(echo $d | sed 's/\/*$//g')
  
  if [ "$RACE" = "true" ]; then
    PGP_PUBLIC_KEY=$PGP_PUBLIC_KEY \
    PGP_PRIVATE_KEY=$PGP_PRIVATE_KEY \
    PGP_PASSPHRASE=$PGP_PASSPHRASE \
    JWT_SIGNER_PUBLIC_KEY=$JWT_SIGNER_PUBLIC_KEY \
    JWT_SIGNER_PRIVATE_KEY=$JWT_SIGNER_PRIVATE_KEY \
    GIN_MODE=release \
    DATABASE_HOST=localhost \
    DATABASE_NAME=vault_dev \
    DATABASE_USER=${DATABASE_USER} \
    DATABASE_PASSWORD=${DATABASE_PASSWORD} \
    IDENT_API_HOST=localhost:8081 \
    IDENT_API_SCHEME=http \
    VAULT_API_HOST=localhost:8082 \
    VAULT_API_SCHEME=http \
    LOG_LEVEL=DEBUG \
    VAULT_USK_VALIDATION_HASH=$VAULT_USK_VALIDATION_HASH
    go test ./... -v \
                       -race \
                       -timeout 1800s \
                       -cover \
                       -coverpkg=./vault/...,./crypto/... \
                       -coverprofile=profile.cov \
                       -tags="$TAGS"
    go tool cover -func profile.cov
    go tool cover -html=profile.cov -o cover.html
  else
    PGP_PUBLIC_KEY=$PGP_PUBLIC_KEY \
    PGP_PRIVATE_KEY=$PGP_PRIVATE_KEY \
    PGP_PASSPHRASE=$PGP_PASSPHRASE \
    JWT_SIGNER_PUBLIC_KEY=$JWT_SIGNER_PUBLIC_KEY \
    JWT_SIGNER_PRIVATE_KEY=$JWT_SIGNER_PRIVATE_KEY \
    GIN_MODE=release \
    DATABASE_HOST=localhost \
    DATABASE_NAME=vault_test \
    DATABASE_USER=${DATABASE_USER} \
    DATABASE_PASSWORD=${DATABASE_PASSWORD} \
    IDENT_API_HOST=localhost:8081 \
    IDENT_API_SCHEME=http \
    VAULT_API_HOST=localhost:8082 \
    VAULT_API_SCHEME=http \
    LOG_LEVEL=DEBUG \
    go test ./... -v \
                       -timeout 1800s \
                       -cover \
                       -coverpkg=./vault/...,./crypto/... \
                       -coverprofile=profile.cov \
                       -tags="$TAGS"
    go tool cover -func profile.cov
    go tool cover -html=profile.cov -o cover.html
  fi
done


docker-compose -f ./ops/docker-compose-db.yml down
docker volume rm ops_vault-db
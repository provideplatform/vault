#!/bin/bash

#
# Copyright 2017-2024 Provide Technologies Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [[ -z "${JWT_SIGNER_PUBLIC_KEY}" ]]; then
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
fi

if [[ -z "${LOG_LEVEL}" ]]; then
  LOG_LEVEL=debug
fi

if [[ -z "${DATABASE_HOST}" ]]; then
  DATABASE_HOST=localhost
fi

if [[ -z "${DATABASE_NAME}" ]]; then
  DATABASE_NAME=vault_dev
fi

if [[ -z "${DATABASE_USER}" ]]; then
  DATABASE_USER=vault
fi

if [[ -z "${DATABASE_PASSWORD}" ]]; then
  DATABASE_PASSWORD=
fi

if [[ -z "${DATABASE_LOGGING}" ]]; then
  DATABASE_LOGGING=false
fi

if [[ -z "${REQUIRE_TLS}" ]]; then
  REQUIRE_TLS=false
fi

if [[ -z "${CONSUME_NATS_STREAMING_SUBSCRIPTIONS}" ]]; then
  CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true
fi

if [[ -z "${NATS_CLUSTER_ID}" ]]; then
  NATS_CLUSTER_ID=provide
fi

if [[ -z "${NATS_TOKEN}" ]]; then
  NATS_TOKEN=testtoken
fi

if [[ -z "${NATS_URL}" ]]; then
  NATS_URL=nats://localhost:4222
fi

if [[ -z "${NATS_STREAMING_URL}" ]]; then
  NATS_STREAMING_URL=nats://localhost:4222
fi

if [[ -z "${NATS_STREAMING_CONCURRENCY}" ]]; then
  NATS_STREAMING_CONCURRENCY=1
fi

if [[ -z "${NATS_FORCE_TLS}" ]]; then
  NATS_FORCE_TLS=false
fi

if [[ -z "${REDIS_HOSTS}" ]]; then
  REDIS_HOSTS=localhost:6379
fi

if [[ -z "${REDIS_DB_INDEX}" ]]; then
  REDIS_DB_INDEX=1
fi

if [[ -z "${REDIS_LOG_LEVEL}" ]]; then
  REDIS_LOG_LEVEL=info
fi

DATABASE_HOST=$DATABASE_HOST DATABASE_USER=$DATABASE_USER DATABASE_PASSWORD=$DATABASE_PASSWORD DATABASE_NAME=$DATABASE_NAME DATABASE_SUPERUSER=$DATABASE_SUPERUSER DATABASE_SUPERUSER_PASSWORD=$DATABASE_SUPERUSER_PASSWORD ./ops/migrate.sh

JWT_SIGNER_PRIVATE_KEY=$JWT_SIGNER_PRIVATE_KEY \
JWT_SIGNER_PUBLIC_KEY=$JWT_SIGNER_PUBLIC_KEY \
CONSUME_NATS_STREAMING_SUBSCRIPTIONS=$CONSUME_NATS_STREAMING_SUBSCRIPTIONS \
NATS_CLUSTER_ID=$NATS_CLUSTER_ID \
NATS_TOKEN=$NATS_TOKEN \
NATS_URL=$NATS_URL \
NATS_STREAMING_URL=$NATS_STREAMING_URL \
NATS_STREAMING_CONCURRENCY=$NATS_STREAMING_CONCURRENCY \
NATS_FORCE_TLS=$NATS_FORCE_TLS \
GIN_MODE=release \
DATABASE_HOST=$DATABASE_HOST \
DATABASE_NAME=$DATABASE_NAME \
DATABASE_LOGGING=$DATABSE_LOGGING \
DATABASE_USER=$DATABASE_USER \
DATABASE_PASSWORD=$DATABASE_PASSWORD \
LOG_LEVEL=$LOG_LEVEL \
REDIS_HOSTS=$REDIS_HOSTS \
REDIS_DB_INDEX=$REDIS_DB_INDEX \
REDIS_LOG_LEVEL=$REDIS_LOG_LEVEL \
SYSLOG_ENDPOINT=$SYSLOG_ENDPOINT \
./.bin/vault_consumer

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

docker compose -f ./ops/docker-compose-db.yml up -d
TAGS=unit ./ops/run_local_tests.sh
docker compose -f ./ops/docker-compose-db.yml down
docker volume rm ops_vault-db

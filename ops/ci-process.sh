#!/bin/bash
#
# Copyright 2017-2022 Provide Technologies Inc.
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

# Script for Continuous Integration
# Example Jenkins usage: 
#       /bin/bash -c \
#           "AWS_ACCESS_KEY_ID=xyz \
#           AWS_SECRET_ACCESS_KEY=abc \
#           AWS_DEFAULT_REGION=us-east-1 \
#           AWS_DEFAULT_OUTPUT=json \
#           ECR_REPOSITORY_NAME=provide/vault \
#           ECS_TASK_DEFINITION_FAMILY=vault \
#           ECS_CLUSTER=production \
#           ECS_SERVICE_NAME=vault \
#           '$WORKSPACE/ops/ci-process.sh'"
set -o errexit # set -e
set -o nounset # set -u
set -o pipefail
# set -o verbose
trap die ERR
die() 
{
    echo "Failed at line $BASH_LINENO"; exit 1
}
echo Executing $0 $*

setup_go() 
{
    if hash go 2>/dev/null
    then
        echo 'Using' `go version`
    else
        echo 'Installing go'
        wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz
        sudo tar -xvf go1.13.linux-amd64.tar.gz
        sudo mv go /usr/lib/go-1.13
        sudo ln -s /usr/lib/go-1.13 /usr/lib/go
        sudo ln -s /usr/lib/go-1.13/bin/go /usr/bin/go
        sudo ln -s /usr/lib/go-1.13/bin/gofmt /usr/bin/gofmt
    fi

    # Set up Go environment to treat this workspace as within GOPATH. 
    export GOPATH=~/go
    export GOBIN=$GOPATH/bin
    export PATH=~/.local/bin:$GOBIN:$PATH
    echo "PATH is: '$PATH'"
    mkdir -p $GOPATH/src/github.com/provideplatform
    mkdir -p $GOBIN

    go env
}

bootstrap_environment() 
{
    echo '....Setting up environment....'
    setup_go
    mkdir -p reports/linters
    echo '....Environment setup complete....'
}

# Preparation
echo '....Running the full continuous integration process....'
scriptDir=`dirname $0`
pushd ${scriptDir}/.. &>/dev/null
echo 'Working Directory =' `pwd`

# The Process
echo '....[PRVD] Setting Up....'
bootstrap_environment

make mod

# (cd vendor/ && tar c .) | (cd src/ && tar xf -)
# rm -rf vendor/

make lint > reports/linters/golint.txt # TODO: add -set_exit_status once we clean current issues up. 

#make test

if [ "$RUN_INTEGRATION_SUITE" = "true" ]; then
  make integration
fi

make build
make ecs_deploy

popd &>/dev/null
echo '....CI process completed....'

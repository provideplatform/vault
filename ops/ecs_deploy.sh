#!/bin/bash

get_build_info()
{
    echo 'Getting build details...'
    revNumber=$(echo `git rev-list HEAD | wc -l`) # the echo trims leading whitespace
    gitHash=`git rev-parse --short HEAD`
    gitBranch=`git rev-parse --abbrev-ref HEAD`
    buildDate=$(date '+%m.%d.%y')
    buildTime=$(date '+%H.%M.%S')
    echo "$(echo `git status` | grep "nothing to commit" > /dev/null 2>&1; if [ "$?" -ne "0" ]; then echo 'Local git status is dirty'; fi )";
    buildRef=${gitBranch}-${gitHash}-${buildDate}-${buildTime}
    echo 'Build Ref =' $buildRef
}

setup_deployment_tools() 
{
    if hash python 2>/dev/null
    then
        echo 'Using: ' 
        python --version
    else
        echo 'Installing python'
        sudo apt-get update
        sudo apt-get -y install python2.7
    fi
    if hash pip 2>/dev/null
    then
        echo 'Using' `pip --version`
    else
        echo 'Installing python'
        sudo apt-get update
        sudo apt-get -y install python-pip
    fi
    if hash aws 2>/dev/null
    then
        echo 'Using AWS CLI: ' 
        aws --version
    else
        echo 'Installing AWS CLI'
        pip install awscli --upgrade --user
    fi
    if hash docker 2>/dev/null
    then
        echo 'Using docker' `docker -v`
    else
        echo 'Installing docker'
        sudo apt-get update
        sudo apt-get install -y apt-transport-https \
                                ca-certificates \
                                software-properties-common
        sudo apt-get install -y docker
    fi
    if hash jq 2>/dev/null
    then
        echo 'Using' `jq --version`
    else
        echo 'Installing jq'
        sudo apt-get update
        sudo apt-get -y install jq
    fi
}

docker_build()
{
    echo 'Docker build...'
    sudo docker build -t provide/vault .

    echo 'Docker tag...'
    sudo docker tag provide/vault:latest "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/provide/vault:${buildRef}"

    echo 'Docker push...'
    aws ecr get-login-password --region ${AWS_DEFAULT_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com
    docker push "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/provide/vault:${buildRef}"
}

ecs_deploy()
{
    DEFINITION_FILE=ecs-task-definition.json
    MUNGED_FILE=ecs-task-definition-UPDATED.json

    echo 'Listing images...'
    ECR_IMAGE_DIGEST=$(aws ecr list-images --repository-name provide/vault | jq '.imageIds[0].imageDigest')

    echo 'Describing images...'
    ECR_IMAGE=$(aws ecr describe-images --repository-name "${ECR_REPOSITORY_NAME}" --image-ids imageDigest="${ECR_IMAGE_DIGEST}" | jq '.')

    echo 'Describing task definitions'
    ECS_TASK_DEFINITION=$(aws ecs describe-task-definition --task-definition "${ECS_TASK_DEFINITION_FAMILY}" | jq '.taskDefinition | del(.taskDefinitionArn) | del(.revision) | del(.status) | del(.compatibilities) | del(.requiresAttributes) | del(.registeredAt) | del(.registeredBy)')

    echo 'Manipulating task defintion...'
    echo $ECS_TASK_DEFINITION > $DEFINITION_FILE
    sed -E "s/vault:[a-zA-Z0-9\.-]+/vault:${buildRef}/g" "./${DEFINITION_FILE}" > "./${MUNGED_FILE}"

    echo 'Registering task-definition...'
    ECS_TASK_DEFINITION_ID=$(aws ecs register-task-definition --family "${ECS_TASK_DEFINITION_FAMILY}" --cli-input-json "file://${MUNGED_FILE}" | jq '.taskDefinition.taskDefinitionArn' | sed -E 's/.*\/(.*)"$/\1/')

    echo 'Updating service...'
    aws ecs update-service --cluster "${ECS_CLUSTER}" --service "${ECS_SERVICE_NAME}" --task-definition "${ECS_TASK_DEFINITION_ID}"
}

if [[ -z "${ECR_REPOSITORY_NAME}" || -z "${ECS_CLUSTER}" || -z "${ECS_TASK_DEFINITION_FAMILY}" || -z "${ECS_SERVICE_NAME}" ]]
then
    echo 'Skipping deployment due to missing environment configuration.'
else
    setup_deployment_tools
    get_build_info
    docker_build
    ecs_deploy
fi

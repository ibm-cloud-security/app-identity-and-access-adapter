#!/usr/bin/env bash
#
# Copyright 2019 APP ID Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

function checkTools() {
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        echo "WARN: script NOT sourced and will not expose image tag"
    fi
    if [[ -z "$(command -v docker)" ]]; then
        echo "Could not find 'docker' in path"
        exit 1
    fi
}

function buildTag() {
    if [[ ! -z $1 ]]; then
        echo $1
        return
    fi
    if [[ -z ${TRAVIS+x} ]]; then
        echo $USER | cut -f1 -d"@"
        return
    fi
    if [[ $TRAVIS_PULL_REQUEST != "false" ]]; then
        echo pr-${TRAVIS_PULL_REQUEST_BRANCH}
        return
    else
        echo branch-${TRAVIS_BRANCH}
        return
    fi
}

function buildAndDeploy() {

    if ! grep -q "https://index.docker.io/v1/" ~/.docker/config.json ; then
        echo "Not logged into Docker. Logging in using env credentials."
        echo ${DOCKER_PASSWORD} | docker login -u ${DOCKER_USERNAME} --password-stdin
    fi

    echo "Building Docker image: ${IMAGE_TAG}"
    docker build -t ${IMAGE_TAG} ${sourceDir}/../.

    echo "Pushing Docker image to container registry"
    docker push ${IMAGE_TAG}
}


IMAGE_REGISTRY_NAMESPACE=${IMAGE_REGISTRY_NAMESPACE:-ibmcloudsecurity}
APP_NAME=${APP_NAME:-app-identity-and-access-adapter}
TAG=$(buildTag $1)
IMAGE_TAG=${IMAGE_REGISTRY_NAMESPACE}/${APP_NAME}:${TAG}
sourceDir="$(dirname "${BASH_SOURCE[0]}")"

# Execute
checkTools
buildAndDeploy
export IMAGE_TEST_TAG=${TAG}

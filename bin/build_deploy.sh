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

# Adapter information
adapterName="ibmcloudappid"
sourceDir="$(dirname "${BASH_SOURCE[0]}")"

function checkEnv() {
    if [[ -z "$(command -v docker)" ]]; then
        echo "Could not find 'docker' in path"
        exit 1
    fi

    if [[ -z "$(command -v helm)" ]]; then
        echo "Could not find 'helm' in path"
        exit 1
    fi
}

function reportError() {
    if [[ $1 -ne 0 ]]; then
        echo $2
        exit $1
    fi
 }

function buildAndTag() {
    echo "Building executable"
    bash -x ${sourceDir}/build_executable.sh
    reportError $? "job has failed, please check the log for details"

    echo "Building and deploying docker image"
    source ${sourceDir}/docker_build_tag_push.sh
}

function installAdapter() {
    echo "Cleaning up cluster"
    helm delete --purge ${adapterName}

    echo "Installing adapter"
    helm install --wait helm/${adapterName} --name ${adapterName} --set image.tag=$1
}

### Execute
checkEnv
buildAndTag
installAdapter "${IMAGE_TEST_TAG}"
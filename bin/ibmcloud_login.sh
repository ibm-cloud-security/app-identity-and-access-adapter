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

## Cluster Information

# Adapter information
adapterName="appidentityandaccessadapter"
sourceDir="$(dirname "${BASH_SOURCE[0]}")"


function checkEnv() {
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
      echo "error this script should be sourced"
      exit 4
    fi

    if [[ -z "$(command -v ibmcloud)" ]]; then
        echo "Could not find 'ibmcloud' in path"
        exit 1
    fi
}

function configureCluster() {
    echo "Logging into IBM Cloud."
    ibmcloud login -r ${REGION} --apikey ${IBM_CLOUD_API_KEY}


    ibmcloud ks cluster-config --cluster ${CLUSTER_NAME}

    local homeDir="home"
    if [[ -z ${TRAVIS+x} ]]; then
        homeDir="Users"
    fi

    echo "Exporting KUBECONFIG=/${homeDir}/${USER}/.bluemix/plugins/container-service/clusters/${CLUSTER_NAME}/kube-config-${DATA_CENTER}-${CLUSTER_NAME}.yml"
    export KUBECONFIG=/${homeDir}/${USER}/.bluemix/plugins/container-service/clusters/${CLUSTER_NAME}/kube-config-${DATA_CENTER}-${CLUSTER_NAME}.yml
}

# Execute
checkEnv
configureCluster
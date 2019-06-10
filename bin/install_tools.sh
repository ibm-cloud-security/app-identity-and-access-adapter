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

function installHelm() {
    wget https://storage.googleapis.com/kubernetes-helm/helm-v2.13.0-linux-amd64.tar.gz
    tar -xvzf helm-v2.13.0-linux-amd64.tar.gz
    sudo mv linux-amd64/helm /usr/local/bin/helm
}

function installIBMCloudCLI() {
    curl -fsSL https://clis.cloud.ibm.com/install/linux | sh
}

function installIBMCloudPlugins() {
    ibmcloud plugin install container-service
}

function installKubectl() {
    curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
    chmod +x ./kubectl
    sudo mv ./kubectl /usr/local/bin/kubectl
}

installHelm
installKubectl
installIBMCloudCLI
installIBMCloudPlugins

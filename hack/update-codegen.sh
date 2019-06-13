#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ${GOPATH}/src/k8s.io/code-generator)}
chmod +x vendor/k8s.io/code-generator/generate-groups.sh
vendor/k8s.io/code-generator/generate-groups.sh all \
  github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/client github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis \
  policies:v1 \
  --go-header-file ${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt

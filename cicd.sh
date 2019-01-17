#!/bin/sh

APP_NAME=istio-adapter-ibmcloudappid
APP_VERSION=latest
IMAGE_REGISTRY_NAMESPACE=antonal80
IMAGE_TAG=${IMAGE_REGISTRY_NAMESPACE}/${APP_NAME}:${APP_VERSION}
KUBE_NAMESPACE=istio-system

echo Building Linux Executable
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo -v -o bin/ibmcloudappid ./cmd/main.go
chmod +x ibmcloudappid

echo Building Image
docker build -t $IMAGE_TAG .

echo Pushing image to Container Registry
docker push $IMAGE_TAG

echo Targeting Cluster
export KUBECONFIG=/Users/antona/.bluemix/plugins/container-service/clusters/secdev1/kube-config-dal13-secdev1.yml

echo Updating ConfigMap
kubectl apply -f kubernetes/configmap.yaml

echo Updating Deployment
kubectl delete deployment dpl-ibmcloudappid --namespace=${KUBE_NAMESPACE} --ignore-not-found=true
kubectl apply -f kubernetes/deployment.yaml

echo Updating Service
kubectl apply -f kubernetes/service.yaml

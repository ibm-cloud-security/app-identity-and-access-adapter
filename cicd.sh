#!/bin/sh

IBM_CLOUD_NAMESPACE=default
APP_NAME=istio-adapter-ibmcloudappid
APP_VERSION=latest
//IMAGE_REGISTRY_URL=registry.ng.bluemix.net
IMAGE_REGISTRY_NAMESPACE=antonal80
IMAGE_TAG=${IMAGE_REGISTRY_NAMESPACE}/${APP_NAME}:${APP_VERSION}
KUBE_NAMESPACE=appid-multi-cloud-manager

echo Targeting default IBM Cloud namespace
#ic target -g $IBM_CLOUD_NAMESPACE

echo Logging-in to Container Registry
#ic cr login

echo Building Image
docker build -t $IMAGE_TAG .

echo Pushing image to Container Registry
docker push $IMAGE_TAG

echo Targeting Cluster
export KUBECONFIG=/Users/antona/.bluemix/plugins/container-service/clusters/anton-dev/kube-config-dal13-anton-dev.yml

echo Updating Namespace
#kubectl apply -f kubernetes/namespace.yaml

#echo Updating ConfigMap
#kubectl apply -f kubernetes/configmap.yaml

echo Updating Image Pull Secret
#kubectl get secret container-registry-credentials --namespace=default --export -o yaml | kubectl apply --namespace=${KUBE_NAMESPACE} -f -

echo Updating Deployment
#kubectl delete deployment dpl-${APP_NAME} --namespace=${KUBE_NAMESPACE} --ignore-not-found=true
#kubectl apply -f kubernetes/deployment.yaml

echo Updating Service
#kubectl apply -f kubernetes/service.yaml

echo Updating TLS Secret
#kubectl get secret anton-dev --namespace=default --export -o yaml | kubectl apply --namespace=${KUBE_NAMESPACE} -f -

echo Deploying Ingress
#kubectl apply -f kubernetes/ingress.yaml

# Build commands
#env GOOS=linux GOARCH=arm go build -a -installsuffix cgo -v -o bin/ibmcloudappid cmd
#env GOOS=linux GOARCH=arm go build -a -installsuffix cgo -v -o bin/ibmcloudappid .
#cd bin/
#ls -la
#chmod +x ibmcloudappid
#./ibmcloudappid
#chmod -x ibmcloudappid
#cd ..
#env GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -a -installsuffix cgo -v -o bin/ibmcloudappid .
#docker build .
#d images

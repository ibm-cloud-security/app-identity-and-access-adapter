APP_NAME=demo
APP_VERSION=latest
IMAGE_REGISTRY_NAMESPACE=aliberat1
IMAGE_TAG=${IMAGE_REGISTRY_NAMESPACE}/${APP_NAME}:${APP_VERSION}

IMAGE_TAG=${IMAGE_REGISTRY_NAMESPACE}/${APP_NAME}:${APP_VERSION}

echo Building Docker image
docker build -t $IMAGE_TAG .

echo Pushing Docker image to container registry
docker push $IMAGE_TAG
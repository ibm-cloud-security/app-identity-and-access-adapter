# Sample App

> Sample app to be used for Istio adapter testing

## Configure and Deploy

1. Enure your kubectl environment to use your second cluster 
2. Inject the Istio sidecar into your deployment
    
```
$ istioctl kube-inject -f ./sample-app.yaml | kubectl apply -f -
```
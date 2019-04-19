# appid-mixer-adapter-plugin

Prototype of App ID integration with Istio.

## Local Development

#### Set Environment

```
// Mandataory Adapter Configuration Fields
export APPID_URL="https://appid-multi-cloud-manager.anton-dev.us-south.containers.mybluemix.net/api"
export APPID_APIKEY="m5pou9gyvw8psqlgnyi9a34fpgbndaidfgr9zs4r"
export CLUSTER_GUID="78901234-aaaa-bbbb-bd0a-f01df6a1f000"
export CLUSTER_NAME="local-test-of-ibmcloudappid-adapter-aaron"
export CLUSTER_LOCATION="aaron's mac"

// Export a path that points to your personal go workspace
export GOPATH=/Users/AaronLiberatore/go-workspace

// Go and Istio Paths
export ISTIO=$GOPATH/src/istio.io
export MIXER_REPO=$GOPATH/src/istio.io/istio/mixer
```

#### Start App ID Adapter

By default the adapter runs on port 47304

```
cd $MIXER_REPO/adapter/ibmcloudappid
go build . && go run cmd/main.go 47304
```

#### Start the Istio Mixer

```
$GOPATH/out/darwin_amd64/release/mixs server --configStoreURL=fs://$GOPATH/src/istio.io/istio/mixer/adapter/ibmcloudappid/testdata --log_output_level=attributes:debug
```

### Testing

To test locally you can send requests directly to the mixer using the following example command.
```
$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer <token>"
```

### Kubernetes

Istio runs inside the `istio-system` kube namespace with each component run in its own pod

#### Deploying

1. Update `cicd.sh` with the locatin of your personal kube configuration
2. Run `sh ./cicd.sh` to build the image, push to docker, and deploy to kubernetes

If you modified the adapters configuration information located under `testdata/sample_operator_cfg.yaml` run the following command:

`kubectl apply -f ./testdata/sample_operator_cfg.yaml`

#### Logs
```
// Follow adapter logs
kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=ibmcloudappid -o jsonpath='{.items[0].metadata.name}')

// Follow mixer logs
kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=telemetry -o jsonpath='{.items[0].metadata.name}') -c mixer
```
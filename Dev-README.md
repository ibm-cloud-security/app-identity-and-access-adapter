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
$GOPATH/out/darwin_amd64/release/mixs server --configStoreURL=fs://$GOPATH/src/ibmcloudappid/adapter/testdata --log_output_level=attributes:debug
```

### Testing

To test locally you can send requests directly to the mixer using the following example command.
```
$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer <token>"

$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC1mODJkYzkxNy0zMDQ3LTRhZjEtOTc3NS02MGUwZTA3ZTFmYWMtMjAxOC0xMi0xOFQxNjoxMDo0Ni40NTkiLCJ2ZXIiOjN9.eyJpc3MiOiJhcHBpZC1vYXV0aC5ldS1nYi5ibHVlbWl4Lm5ldCIsImV4cCI6MTU1NjE1NDIwMiwiYXVkIjoiMWJmZDJkY2UtODE4My00ODcxLTg4ZjctYWNmYmY5MzZhMjI4Iiwic3ViIjoiMWJmZDJkY2UtODE4My00ODcxLTg4ZjctYWNmYmY5MzZhMjI4IiwiYW1yIjpbImFwcGlkX2NsaWVudF9jcmVkZW50aWFscyJdLCJpYXQiOjE1NTYxNTA2MDIsInRlbmFudCI6ImY4MmRjOTE3LTMwNDctNGFmMS05Nzc1LTYwZTBlMDdlMWZhYyIsInNjb3BlIjoiYXBwaWRfZGVmYXVsdCJ9.j2iDkDXJpFAHQRE2bSJpfIh-2Q25993otU0KMrya6EpSpd00COeRqLeRSilY3hu9hvMLcK1R4iK1ouSb2pRdSoeE69rhE42V8rhSeYQqkA5TphLnBxywn-ftCL4UbwfRlG7A-g0h7UjYKs-JfMz2R9Q6BfI41Vd-WsM6GPdQgMdEMaIwys3DwWhLRvTUapPvsGfmioKeFQj9hkKANuiC7OIjnXIFTlQob75Sr3ezTr8YTJeC9c2Mg3UB-CjFJi84J6NJHWgsYN4O-RsTV_sEYxhGKajQHD9Km_2Mf51gQkXbBaiU2wWRm23X_5qejuugZN_mC5RWzylZx7xJEd9U8A" --string_attributes destination.service.host=any
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


### Installation 

Policy checks must be enabled!!!
```
--set global.disablePolicyChecks=false
```
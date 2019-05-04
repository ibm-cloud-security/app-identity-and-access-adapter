# appid-mixer-adapter-plugin

Prototype of App ID integration with Istio.

## Local Development

#### Set Environment

```
export GOPATH=/Users/AaronLiberatore/go-workspace
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
$GOPATH/out/darwin_amd64/release/mixs server --configStoreURL=fs://$GOPATH/src/ibmcloudappid/test/testdata --log_output_level=attributes:debug
```

### Testing

To test locally you can send requests directly to the mixer using the following example command.
```
$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer <token>"

$GOPATH/out/darwin_amd64/release/mixc check --stringmap_attributes "request.query_params=code:asdf,request.headers=authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC1mODJkYzkxNy0zMDQ3LTRhZjEtOTc3NS02MGUwZTA3ZTFmYWMtMjAxOC0xMi0xOFQxNjoxMDo0Ni40NTkiLCJ2ZXIiOjN9.eyJpc3MiOiJhcHBpZC1vYXV0aC5ldS1nYi5ibHVlbWl4Lm5ldCIsImV4cCI6MTU1NjE1NDIwMiwiYXVkIjoiMWJmZDJkY2UtODE4My00ODcxLTg4ZjctYWNmYmY5MzZhMjI4Iiwic3ViIjoiMWJmZDJkY2UtODE4My00ODcxLTg4ZjctYWNmYmY5MzZhMjI4IiwiYW1yIjpbImFwcGlkX2NsaWVudF9jcmVkZW50aWFscyJdLCJpYXQiOjE1NTYxNTA2MDIsInRlbmFudCI6ImY4MmRjOTE3LTMwNDctNGFmMS05Nzc1LTYwZTBlMDdlMWZhYyIsInNjb3BlIjoiYXBwaWRfZGVmYXVsdCJ9.j2iDkDXJpFAHQRE2bSJpfIh-2Q25993otU0KMrya6EpSpd00COeRqLeRSilY3hu9hvMLcK1R4iK1ouSb2pRdSoeE69rhE42V8rhSeYQqkA5TphLnBxywn-ftCL4UbwfRlG7A-g0h7UjYKs-JfMz2R9Q6BfI41Vd-WsM6GPdQgMdEMaIwys3DwWhLRvTUapPvsGfmioKeFQj9hkKANuiC7OIjnXIFTlQob75Sr3ezTr8YTJeC9c2Mg3UB-CjFJi84J6NJHWgsYN4O-RsTV_sEYxhGKajQHD9Km_2Mf51gQkXbBaiU2wWRm23X_5qejuugZN_mC5RWzylZx7xJEd9U8A" --string_attributes request.url_path=/api/user/data,request.method=GET,destination.namespace=multi-cloud-tech-preview,destination.service.name=svc-hello-world-backend,destination.service.namespace=multi-cloud-tech-preview
```

### Kubernetes

Istio runs inside the `istio-system` kube namespace with each component run in its own pod

#### Deploying

1. Create executable `sh build_executable.sh`
2. Deploy docker images `sh build_executable.sh`
3. Apply helm chart

`helm install ./helm/ibmcloudappid --name ibmcloudappid`

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
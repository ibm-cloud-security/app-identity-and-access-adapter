# OIDC/JWT Authentication Mixer Adapter Plugin Dev Information

> OIDC integration with Istio.

### Local Development

You will need Istio running in a cluster (locally use Minikube). 

Tools:
- [Minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
- [Istio - Minikube](https://istio.io/docs/setup/kubernetes/prepare/platform-setup/minikube/)
- [Istio Source](https://github.com/istio/istio)
- Helm
- Kubectl
- Istioctl

> Important note on Istio Installation 

Policy checks must be enabled
```
--set global.disablePolicyChecks=false
```

### Environment

If using Istio shell scripts, ensure the following commands are exported in your environment.

```
export GOPATH=~/go-workspace
export ISTIO=$GOPATH/src/istio.io
export MIXER_REPO=$GOPATH/src/istio.io/istio/mixer
```

### Protobuf Definitions

Protobuf templates define the gRPC communication interface between Mixer and our Adapter. 

#### Building the template

Version 0.0.0 uses a custom template defining it's input and output.

You can see the template at `ibmcloudappid/config/template/template.proto`.

Whenever you want the adapter to take in or output new parameters, you will have to rebuild template using Istio's bundled script.

Run the following command under Istio root to generate the code stubs for the new template:

```bash
bin/mixer_codegen.sh -t ./path/to/config/template/template.proto
```

#### Building the adapter config

To implement an adapter for the updated template, will need to updates its configuration. 


Modify the file `ibmcloudappid/config/adapter/config.proto` with the following content:

Run the following command to generate the adapter definition:

```bash
bin/mixer_codegen.sh -a ./path/to/config/adapter/config.proto -x "-s=false -n ibmcloudappid -t authnZ"
```

This command produces a session-less adapter called `ibmcloudappid` that implements the template `authnZ`.

### Testing outside of a cluster

1. Start the Istio Mixer

    ```
    $GOPATH/out/darwin_amd64/release/mixs server --configStoreURL=fs://$GOPATH/src/ibmcloudappid/test/testdata --log_output_level=attributes:debug
    ```

2. Start the adapter
    
    ```bash
    # By default the adapter runs on port 47304
    go build ./... && go run cmd/main.go 47304
    ```

3. Test JWT Request

    ```bash
    $GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer <token>"    
    ```
        
4. Test OIDC Request
    
    ```bash     
    $GOPATH/out/darwin_amd64/release/mixc check --stringmap_attributes "request.query_params=code:asdf,request.headers=authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC1mODJkYzkxNy0zMDQ3LTRhZjEtOTc3NS02MGUwZTA3ZTFmYWMtMjAxOC0xMi0xOFQxNjoxMDo0Ni40NTkiLCJ2ZXIiOjN9.eyJpc3MiOiJhcHBpZC1vYXV0aC5ldS1nYi5ibHVlbWl4Lm5ldCIsImV4cCI6MTU1NjE1NDIwMiwiYXVkIjoiMWJmZDJkY2UtODE4My00ODcxLTg4ZjctYWNmYmY5MzZhMjI4Iiwic3ViIjoiMWJmZDJkY2UtODE4My00ODcxLTg4ZjctYWNmYmY5MzZhMjI4IiwiYW1yIjpbImFwcGlkX2NsaWVudF9jcmVkZW50aWFscyJdLCJpYXQiOjE1NTYxNTA2MDIsInRlbmFudCI6ImY4MmRjOTE3LTMwNDctNGFmMS05Nzc1LTYwZTBlMDdlMWZhYyIsInNjb3BlIjoiYXBwaWRfZGVmYXVsdCJ9.j2iDkDXJpFAHQRE2bSJpfIh-2Q25993otU0KMrya6EpSpd00COeRqLeRSilY3hu9hvMLcK1R4iK1ouSb2pRdSoeE69rhE42V8rhSeYQqkA5TphLnBxywn-ftCL4UbwfRlG7A-g0h7UjYKs-JfMz2R9Q6BfI41Vd-WsM6GPdQgMdEMaIwys3DwWhLRvTUapPvsGfmioKeFQj9hkKANuiC7OIjnXIFTlQob75Sr3ezTr8YTJeC9c2Mg3UB-CjFJi84J6NJHWgsYN4O-RsTV_sEYxhGKajQHD9Km_2Mf51gQkXbBaiU2wWRm23X_5qejuugZN_mC5RWzylZx7xJEd9U8A" --string_attributes request.url_path=/api/user/data,request.method=GET,destination.namespace=multi-cloud-tech-preview,destination.service.name=svc-hello-world-backend,destination.service.namespace=multi-cloud-tech-preview
    ```

### Testing within a cluster

1. Deploy a Sample app to an Istio enabled cluster
    > Ensure the cluster has policy checks enabled and the app pod is Istio enabled

2. Update the Helm chart and `build_adapter_dockers.sh` with your Docker account.

3. Create executable 
    
    `sh build_executable.sh`

4. Deploy docker images 

    `sh build_adapter_dockers.sh`

5. Deploy the adapter

    `helm install ./helm/ibmcloudappid --name ibmcloudappid`
   
4. Apply policies and make requests to your adapter

#### Logs
```
// Follow adapter logs
kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=ibmcloudappid -o jsonpath='{.items[0].metadata.name}')

// Follow mixer logs
kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=telemetry -o jsonpath='{.items[0].metadata.name}') -c mixer
```
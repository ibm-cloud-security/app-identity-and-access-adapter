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

Version 0.0.0 uses a custom template defining its input and output.

You can see the template at `github.com/ibm-cloud-security/app-identity-and-access-adapter/config/template/template.proto`.

Whenever you want the adapter to take in or output new parameters, you will have to rebuild template using Istio's bundled script.

Run the following command under your Istio repository's root folder to generate the code stubs for the new template:

```bash
bin/mixer_codegen.sh -t ./path/to/config/template/template.proto
```

#### Building the adapter config

To implement an adapter for the updated template, you will need to updates its configuration. 

Modify the file `github.com/ibm-cloud-security/app-identity-and-access-adapter/config/adapter/config.proto` with the following content:

Run the following command to generate the adapter definition:

```bash
bin/mixer_codegen.sh -a ./path/to/config/adapter/config.proto -x "-s=false -n appidentityandaccessadapter -t authnZ"
```

This command produces a session-less adapter called `appidentityandaccessadapter` that implements the template `authnZ`.

### Testing outside of a cluster

> Note: Adjust paths as necessary

1. Start the Istio Mixer

    ```
    $GOPATH/out/darwin_amd64/release/mixs server --configStoreURL=fs://$GOPATH/src/github.com/ibm-cloud-security/app-identity-and-access-adapter/test/testdata --log_output_level=attributes:debug
    ```

2. Start the adapter
    
    ```bash
    # By default the adapter runs on port 47304
    go build ./... && go run cmd/main.go 47304
    ```

3. Test JWT Request

    ```bash
    ../go-workspace-appid/out/darwin_amd64/release/mixc check --string_attributes request.url_path=/api,request.method=GET,destination.service.name=svc-sample-app,destination.service.namespace=sample-app --stringmap_attributes "request.headers=authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwcElkLTcxYjM0ODkwLWE5NGYtNGVmMi1hNGI2LWNlMDk0YWE2ODA5Mi0yMDE4LTA4LTAyVDExOjUzOjM2LjQ5NyIsInZlciI6NH0.eyJpc3MiOiJodHRwczovL2V1LWdiLmFwcGlkLnRlc3QuY2xvdWQuaWJtLmNvbS9vYXV0aC92NC83MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJleHAiOjE1NjEwMDU5ODEsImF1ZCI6WyJmMTZhZTViNy0wNmZmLTQxOTEtOWE2Ny0zN2EwNmNiNzEwYWQiXSwic3ViIjoiZjE2YWU1YjctMDZmZi00MTkxLTlhNjctMzdhMDZjYjcxMGFkIiwiYW1yIjpbImFwcGlkX2NsaWVudF9jcmVkZW50aWFscyJdLCJpYXQiOjE1NjEwMDIzODEsInRlbmFudCI6IjcxYjM0ODkwLWE5NGYtNGVmMi1hNGI2LWNlMDk0YWE2ODA5MiIsInNjb3BlIjoiYXBwaWRfZGVmYXVsdCJ9.QxjshCrPB5Ewr-Xt9JB75LzpTCnPhZv2nb4KbhiI2z4XpNOPJAfYyiaRon_IZJERc9aggVOjUzg8q9M3PFNY4HCVc7yTzKDNjlxDX4Cy_I0VsMjq1j_zSodLAO_JNKrdw-eUhAaZm2dusqegju-RjYYQaRLvdl04ULtwyA7j1M42Pa-ucwSZy0cWkQl1ucNVR4ydYQQtX81dliauRL3m605vkW0cjFYeMJvLWluoeMfbmBQAEINl4Vgd6LeZmiR0rFKKHtOptc8ZISqrnWULEZPVDkg2A3KKcW5sXyf-dtb2UpXJCf66-auwYYgCJ7rzjxrblSji3aK4DucZHDxEBA"    
    ```
        
4. Test OIDC Request
    
    ```bash 
    // Callback    
    $GOPATH/out/darwin_amd64/release/mixc check --string_attributes request.url_path=/web/home/oidc/callback,request.method=GET,destination.service.name=svc-sample-app,destination.service.namespace=sample-app --stringmap_attributes "request.query_params=code:OKVBoNZcnzbeYXOOY399xuKd61xFqc"    ```
    ```
    
### Testing within a cluster

1. Deploy a Sample app to an Istio enabled cluster
    > Ensure the cluster has policy checks enabled and the app pod is Istio enabled

2. Update the Helm chart to use the requested paramters.

3. Build the executable, deploy the docker image, and then deploy the adapter

`sh build_deploy.sh`
   
4. Apply policies and make requests to your adapter

#### Logs

```
// Follow adapter logs
export adapter_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=appidentityandaccessadapter -o jsonpath='{.items[0].metadata.name}')

// Follow mixer logs
export mixer_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=telemetry -o jsonpath='{.items[0].metadata.name}') -c mixer
```

**Note:** 
   
   If viewing JSON logs you may want to tail the logs and pretty print them using [jq](https://brewinstall.org/install-jq-on-mac-with-brew/)
   
   ```bash
    $ adapter_logs | jq
   ```

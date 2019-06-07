# IBM Cloud App ID Istio Adapter

[![Go Report Card](https://goreportcard.com/badge/github.com/ibm-cloud-security/policy-enforcer-mixer-adapter)](https://goreportcard.com/report/github.com/ibm-cloud-security/policy-enforcer-mixer-adapter)

[![IBM Cloud powered][img-ibmcloud-powered]][url-ibmcloud]
[![Travis][img-travis-master]][url-travis-master]
[![Coveralls][img-coveralls-master]][url-coveralls-master]
[![Codacy][img-codacy]][url-codacy]

[![GithubWatch][img-github-watchers]][url-github-watchers]
[![GithubStars][img-github-stars]][url-github-stars]
[![GithubForks][img-github-forks]][url-github-forks]

## Summary

The IBM Cloud App ID Istio Mixer adapter facilitates authentication and access management across an Istio service mesh. The adapter can be configured with an OIDC / OAuth 2.0 compliant identity provider enabling it to seamlessly control authorization and access management in heterogeneous environments. 

The adapter supports OIDC / OAuth 2.0 and JWT OAuth 2.0 Bearer Token workflows.

### Architecture

The Istio service mesh uses an Envoy proxy sidecar to mediate all inbound and outbound traffic for all services in the service mesh.

This deployment allows Istio to extract a wealth of signals about traffic behavior as attributes, which can inturn be sent to Mixer to enforce policy decisions.

Situated behind Mixer, the IBM Cloud App ID adapter processes these attributes against custom defined policies to control identity and access management into and throughout the service mesh.

![Istio Mixer Architecture](https://istio.io/docs/concepts/policies-and-telemetry/topology-without-cache.svg "Istio Mixer Architecture")

> See the section on [Policy Configuration](#policy-configuration) for information on configuring OIDC / OAuth 2.0 policies

### Adapter Installation

The adapter can be installed using the accompanying helm chart. The chart comes with an opinionated 
set of configuration values that may be updated depending on project need.

Once your chart is configured, you will need to install `helm` followed by the adapter chart using the commands below:

#### Requirements

- [Kubernetes Cluster](https://kubernetes.io/)
- [Istio Service Mesh](https://istio.io/)
- [Helm](https://helm.sh/)


```bash
$ helm init
$ helm install ./helm/ibmcloudappid --name ibmcloudappid
```

### Helm Chart Configuration

The default values can be seen and updated [here](./helm/values.yaml)

#### Logging

By default, the adapter logs at an INFO visibility level with a JSON styled output for ease of integration with logging systems.

**Note:** If viewing JSON logs manually you may want to tail the logs and pretty print them using [jq](https://brewinstall.org/install-jq-on-mac-with-brew/)

You can update this configuration in the helm chart. Supported log levels range from [-1, 7] following the model of zapcore. See the [docs](https://godoc.org/go.uber.org/zap/zapcore#Level) for level details.

### Policy Configuration

```helmyaml
kind: OidcConfig
  metadata:
    name: oidc-provider-config
    namespace: sample-namespace
  spec:
    discoveryUrl: https://example-provider.com/oidc/.well-known/configuration
    clientId: my-oidc-client-seidcret
    clientSecretRef: my-oidc-client-secret
```

```helmyaml
kind: JwtConfig
  metadata:
    name: jwt-provider-config-1
    namespace: sample-namespace
  spec:
    jwksUrl: https://example-provider.com/oauth2/publickeys
```

```helmyaml
kind: Policy
  metadata:
    name: policy-1
    namespace: sample-namespace
  spec:
    targets:
      - service: svc-aaa
        paths: 
         - exact: /web
           method: GET
           policies: 
           - type: oidc
             config: oidc-provider-config-1  
        - prefix: /api
          policies:
           - type: jwt
             config: jwt-provider-config-1 
```

### Debugging

**Note:** If viewing JSON logs manually you may want to tail the logs and pretty print them using [jq](https://brewinstall.org/install-jq-on-mac-with-brew/)

#### Adapter

```bash
$ export adapter_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=ibmcloudappid -o jsonpath='{.items[0].metadata.name}')
$ adapter_logs | jq
```

#### Mixer

```bash
$ export mixer_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=telemetry -o jsonpath='{.items[0].metadata.name}') -c mixer
$ mixer_logs
```

### Cleanup

```bash
$ helm delete --purge ibmcloudappid
$ kubectl delete rule ibmcloudappid-keys -n istio-system
```

### License
This package contains code licensed under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 and may also view the License in the LICENSE file within this package.

[img-ibmcloud-powered]: https://img.shields.io/badge/ibm%20cloud-powered-blue.svg
[url-ibmcloud]: https://www.ibm.com/cloud/
[img-license]: https://img.shields.io/npm/l/ibmcloud-appid.svg
[img-version]: https://img.shields.io/npm/v/ibmcloud-appid.svg

[img-github-watchers]: https://img.shields.io/github/watchers/ibm-cloud-security/policy-enforcer-mixer-adapter.svg?style=social&label=Watch
[url-github-watchers]: https://github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/watchers
[img-github-stars]: https://img.shields.io/github/stars/ibm-cloud-security/appid-serversdk-nodejs.svg?style=social&label=Star
[url-github-stars]: https://github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/stargazers
[img-github-forks]: https://img.shields.io/github/forks/ibm-cloud-security/policy-enforcer-mixer-adapter.svg?style=social&label=Fork
[url-github-forks]: https://github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/network

[img-travis-master]: https://travis-ci.org/ibm-cloud-security/policy-enforcer-mixer-adapter.svg?branch=development
[url-travis-master]: https://travis-ci.org/ibm-cloud-security/policy-enforcer-mixer-adapter

[img-coveralls-master]: https://coveralls.io/repos/github/ibm-cloud-security/policy-enforcer-mixer-adapter/badge.svg
[url-coveralls-master]: https://coveralls.io/github/ibm-cloud-security/policy-enforcer-mixer-adapter
[img-codacy]: https://api.codacy.com/project/badge/Grade/2dd243b5b9f64431bf03bf0a9a470833?branch=master
[url-codacy]: https://app.codacy.com/app/sandmman/policy-enforcer-mixer-adapter?utm_source=github.com&utm_medium=referral&utm_content=ibm-cloud-security/policy-enforcer-mixer-adapter&utm_campaign=Badge_Grade_Dashboard

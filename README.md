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

The IBM Cloud App ID Istio Mixer adapter manages authentication and access management across your Istio service mesh. The adapter can be configured with any OIDC / OAuth 2.0 compliant identity provider enabling it to seamlessly control authorization and access management in many heterogeneous environments.

The adapter supports OIDC / OAuth 2.0 and JWT OAuth 2.0 Bearer Token workflows to protect both frontend and backend applications.

### Architecture

The Istio service mesh uses an Envoy proxy sidecar to mediate all inbound and outbound traffic for all services in the service mesh.

This deployment allows Istio to extract a wealth of signals about traffic behavior, which can in turn be sent to Mixer to enforce policy decisions.

Situated behind Mixer, the IBM Cloud App ID adapter processes these attributes against custom defined policies to control identity and access management into and across the service mesh.

![Istio Mixer Architecture](https://istio.io/docs/concepts/policies-and-telemetry/topology-without-cache.svg "Istio Mixer Architecture")

> See the section on [Policy Configuration](#policy-configuration) for information on configuring OIDC / OAuth 2.0 policies

Once connected to the service mesh, custom access management policies can be created, updated, and deleted without redeploying applications or code changes changes. These policies are specific to Kubernetes services and can be finely tuned to specific service endpoints.

The Auth 2.0 / OIDC adapter provides support for two types of access control flows corresponding to frontend and backend access control respectively:
1. [OAuth 2.0 Authorization Bearer](https://tools.ietf.org/html/rfc6750)

2. [Open ID Connect (OIDC)](https://openid.net/specs/openid-connect-core-1_0.html)

#### API Protection

The OAuth 2.0 Authorization Bearer flow is used for protecting service APIs by validating JWT Bearer tokens in the authorization header. Unauthenticated clients will be returned HTTP 401 response status with a list of scopes needed to obtain authorization.

This authorization flow expects request to contain an Authorization header with valid access token and optional identity token. See App ID docs for additional information. The expected header structure is `Authorization=Bearer {access_token} [{id_token}]`

In case of invalid/expired tokens the APIStrategy will return HTTP 401 with `Www-Authenticate=Bearer scope="{scope}" error="{error}"`. The error component is optional.

Fo information, on configuring OAuth 2.0 Authorization Bearer see [Protecting APIs](#protecting-apis) below.

#### Frontend Protection

Browser based applications can use the OIDC / OAuth 2.0 authorization_grant flow to authenticate users on frontend applications.

When an unauthenticated user is detected, they are automatically redirected to the authentication page. Once authentication completes, the browser is redirected to an implicit `/oidc/callback` endpoint where the adapter intercepts the request, obtains tokens from the identity providers, and then redirects the user back to their originally requested URL.

Protected applications endpoints can view the user session information using the `Authorization` header, which will contain the session tokens.

    Authorization: Bearer <access_token> <id_token>`

Authenticated users can then logout by access any protected endpoint with the `/oidc/logout` suffix.

    https://myhost/path/oidc/logout

Refresh Token may be used to acquire new access and identity tokens automatically without the need to re-authenticate. If the configured IdP returns a refresh token, it will be persisted in the session and used to retrieve new tokens once the identity token has expired.

>> **WARNING:** Due to a bug within Istio, the adapter currently stores user session internally and is not persisted across replicates or over failover. Users using the adapter should limit their workloads to a single replica until the bug is addressed in the next release.

### Installation and usage

The adapter can be installed using the accompanying helm chart. The chart comes with an opinionated set of configuration values that may be updated depending on project needs.

#### Prerequisites

- [Kubernetes Cluster](https://kubernetes.io/)
- [Istio v1.1](https://istio.io/docs/setup/kubernetes/install/)
- [Helm](https://helm.sh/)

#### Adapter Installation

1. If not already installed, install helm in you cluster
    ```bash
    $ helm init
    ```

2. Update the helm chart [here](./helm/values.yaml) with your custom configuration

3. Install the Adapter Helm chart
    ```bash
    $ helm install ./helm/ibmcloudappid --name ibmcloudappid
    ```

### Authorization and Authentication Policies

In order to apply authorization and access policies, you will need to define an identity provider with an authorization server configuration in addition to a policy outlining when a particular access control flow should be used.

>> See example CRDs, under the [samples directory](./samples/crds)

#### OAuth 2.0 JWT Bearer Policies

The OAuth 2.0 Bearer token spec defines a pattern for protecting APIs using JSON Web Tokens [(JWTs)](https://tools.ietf.org/html/rfc7519.html).

The adapter supports configuring OAuth Bearer API protection by:

1. Defining a `JwtConfig` CRD containing the public key resource.

2. Registering server endpoints within a `Policy` CRD to validate incoming requests

##### OAuth 2.0 Authorization Bearer Configuration Resource

```helmyaml
kind: JwtConfig
  metadata:
    name: jwt-provider-config-1
    namespace: sample-namespace
  spec:
    jwksUrl: <oauth-provider-jwks-endpoint>
```

| Field   |     Type      |Required|     Description      |
|----------|:-------------:|:-------------:|
| jwksUrl |string|yes|  The endpoint containing a JSON object representing a set of JSON Web Keys (JWKs) required to verify the authenticity of issued ID and access tokens.  |

#### Protecting Frontend Applications

Frontend applications requiring user authentication can be configured to use the OIDC / Auth 2.0 authentication flow.

To protect frontend applications you will need to:

1. Define an `OidcConfig` CRD containing the client used to facilitate the authentication flow with the Identity provider.

2. Register server endpoints within a `Policy` CRD to protect incoming requests

##### OAuth 2.0 /  OIDC Configuration Resource

```helmyaml
kind: OidcConfig
  metadata:
    name: oidc-provider-config
    namespace: sample-namespace
  spec:
    discoveryUrl: <oidc-provider-well-known-endpoint>
    clientId: <oauth2-client-id>
    clientSecret: <oauth2-plain-text-client-secret>
    clientSecretRef:
        name: <name-of-my-kube-secret>
        key: <key-in-my-kube-secret>
```

| Field   | Type |Required|      Description      |
|----------|:-------------:|:-------------:|
| discoveryUrl |string|yes| well-known endpoint containing a JSON document of OIDC/OAuth 2.0 configuration information |
| clientId |string|yes| identifier for the client used for authentication  |
| clientSecret | string|*no|  plaintext secret used to authenticate the client. If not provided, a `clientSecretRef` must exist. |
| clientSecretRef |object|*no| reference secret used to authenticate the client. This may be used in place of the plaintext `clientSecret`  |
| clientSecretRef.name |string|yes| name of the Kubernetes Secret containing the clientSecret  |
| clientSecretRef.key |string|yes| field within the Kubernetes Secret containing the clientSecret   |

###### Policy Resource

Policies can be configured using the Policy CRD. Each Policy applies exclusively to the Kubernetes namespace in which the object lives and can specify the services, paths, and methods which should be protected.

```helmyaml
kind: Policy
  metadata:
    name: policy-1
    namespace: sample-namespace
  spec:
    targets:
      - service: svc-service-name-123
        paths: 
         - exact: /web
           method: GET
           policies: 
           - type: oidc
             config: <name-OidcConfig-resource>
        - prefix: /api
          policies:
           - type: jwt
             config: <name-JwtConfig-resource>
```

| Service Object   |     Type      |Required|     Description      |
|----------|:-------------:|:-------------:|
| service |string|yes| name of Kubernetes service in the Policy namespace to protect |
| paths | array |yes| list of path objects defining endpoints to protect. If an empty array, all paths are protected |

| Path Object   |     Type      |Required|     Description      |
|----------|:-------------:|:-------------:|
| exact or prefix |string|yes| path to apply the policies onto. Exact matches endpoints exactly as provided with the last `/` trimmed. Prefix matches endpoints beginning with the route prefix provided |
| method |enum|no| The HTTP method protected. Valid options ALL, GET, PUT, POST, DELETE, PATCH - Defaults to ALL:  |
| policies |array|no| The OIDC/JWT policies that should be applied.  |

| Policy Object   |     Type     | Required |     Description      |
|----------|:-------------:|:-------------:|
| type |enum|yes| type of OIDC policy: `jwt` or `oidc` |
| config |string|yes| name of provider config to use |

### Cleanup

The adapter and all associated CRDs can be removed by deleting the helm chart.

```bash
$ helm delete --purge ibmcloudappid
$ kubectl delete rule ibmcloudappid-keys -n istio-system
```

### Debugging

#### Logging

By default, the adapter logs at an INFO visibility level with a JSON styled output for ease of integration with external logging systems.

You can update this configuration in the helm chart. Supported log levels range from [-1, 7] following from zapcore. See their [docs](https://godoc.org/go.uber.org/zap/zapcore#Level) for level details.

>> **Note:** If viewing JSON logs manually you may want to tail the logs and pretty print them using [jq](https://brewinstall.org/install-jq-on-mac-with-brew/). Check the section on [debugging](#debugging) for additional details

#### Adapter

To see the adapter logs, you can use `kubectl` or access the pod from the `ibmcloudappid` pod from the Kubernetes console.

```bash
$ export adapter_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=ibmcloudappid -o jsonpath='{.items[0].metadata.name}')
$ adapter_logs | jq
```

#### Mixer

In the event, the adapter does not appear to be receiving requests check the Mixer logs to ensure it has connected to the adapter succesfully.

```bash
$ export mixer_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=telemetry -o jsonpath='{.items[0].metadata.name}') -c mixer
$ mixer_logs
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

# IBM Cloud App ID Istio Adapter

[![Go Report Card](https://goreportcard.com/badge/github.com/ibm-cloud-security/app-identity-and-access-adapter)](https://goreportcard.com/report/github.com/ibm-cloud-security/app-identity-and-access-adapter)

[![IBM Cloud powered][img-ibmcloud-powered]][url-ibmcloud]
[![Travis][img-travis-master]][url-travis-master]
[![Coveralls][img-coveralls-master]][url-coveralls-master]
[![Codacy][img-codacy]][url-codacy]

[![GithubWatch][img-github-watchers]][url-github-watchers]
[![GithubStars][img-github-stars]][url-github-stars]
[![GithubForks][img-github-forks]][url-github-forks]


With the [IBM Cloud App ID](https://cloud.ibm.com/services/appid) Istio Mixer Adapter, you can manage authentication and access management across your service mesh. The Adapter can be configured with any OIDC or OAuth 2.0 compliant identity provider, which enables it to seamlessly control authentication and authorization policies in many heterogeneous environments, including frontend and backend applications.
{: shortdesc}


## Architecture

Istio uses an Envoy proxy sidecar to mediate all inbound and outbound traffic for all services in the service mesh. By using the proxy, Istio extracts information about traffic behavior that can then be sent to the Mixer to enforce policy decisions. The IBM Cloud App ID adapter analyzes these attributes against custom policies to control identity and access management into and across the service mesh. These access management policies are linked to particular Kubernetes services and can be finely tuned to specific service endpoints. Using the adapter, these policies can be created, updated, and deleted without redeploying applications or changing your code in any way. 

The App ID adapter provides support for two different access control flows that correspond to the frontend and backend of your apps respectively. 

1. [OAuth 2.0 Authorization Bearer](https://tools.ietf.org/html/rfc6750)

2. [Open ID Connect (OIDC)](https://openid.net/specs/openid-connect-core-1_0.html)

For more information about configuring OIDC and OAuth 2.0, see [Policy configuration](#Defining-a-Configuration). To see how App ID fits into the Istio architecture, check out the following diagram.


![Istio Mixer Architecture](https://istio.io/docs/concepts/policies-and-telemetry/topology-without-cache.svg "Istio Mixer Architecture")

* The Envoy sidecar "proxy" sits in front of your application and calls the Mixer with telemetry before each request.
* The Mixer dispatches the telemetry to the App ID authentication/ access management Adapter.
* The Adapter evaulates the authentication and authorization policies on the request telemetry and returns response - access granted or denied.
* The proxy responds:
    * When successful, the proxy forwards the request to the service or application.
    * On failure, the proxy returns a failure check response to the calling client - the user or another app.



### API Protection

The App ID Adapter can be used in collaboration with the OAuth 2.0 Authorization Bearer flow to protect service APIs by validating JWT Bearer tokens. The Bearer flow expects a request to contain an Authorization header with a valid access token and optionally, an identity token. The expected header structure is `Authorization=Bearer {access_token} [{id_token}]`. Unauthenticated clients are returned an HTTP 401 response status with a list of the scopes that are needed to obtain authorization. If the tokens are invalid or expired, the API strategy returns an `HTTP 401` response with an optional error component identifying the case of the error `Www-Authenticate=Bearer scope="{scope}" error="{error}"`.


For more information about tokens and how they're used, see the App ID documentation. For information, on configuring the OAuth 2.0 Authorization Bearer for the adapter, see [Protecting APIs](#protecting-apis).


### Frontend Protection

If you're using a browser based application, you can use the OIDC / Auth 2.0 `authorization_grant` flow to authenticate your users. When an unauthenticated user is detected, they are automatically redirected to the authentication page. When the authentication completes, the browser is redirected to an implicit `/oidc/callback` endpoint where the adapter intercepts the request. At this point, the adapter obtains tokens from the identity provider and then redirects the user back to their originally requested URL. 

To view the user session information, including the session tokens, you can look in the `Authorization` header.

```
Authorization: Bearer <access_token> <id_token>
```

You can also logout authenticated users. When an authenticated user accesses any protected endpoint with `/oidc/logout` appended as shown in the following example, they are logged out from their current session.

```
https://myhost/path/oidc/logout
```

If needed, a refresh token can be used to automatically acquire new access and identity tokens without your user's needing to re-authenticate. If the configured identity provider returns a refresh token, it is persisted in the session and used to retreive new tokens when the identity token expires.

Due to a bug within Istio, the adapter currently stores user session information internally and does *not* persist the information across replicas or over failover configurations. When using the adapter, users should limit their workloads to a single replica until the bug is addressed in the next release.



## Installation and usage

You can install the Adapter by using the accompanying Helm chart. You can configure the chart to match the needs of your project.


### Before you begin

Before you get started, be sure you have the following prerequisites installed.

- [Kubernetes Cluster](https://kubernetes.io/)
- [Istio v1.1](https://istio.io/docs/setup/kubernetes/install/)
- [Helm](https://helm.sh/)


### Adapter Installation

To install the chart, initialize Helm in your cluster, define the options that you want to use, and then run the install command.

1. If you haven't already, install Helm in your cluster.
    ```bash
    $ helm init
    ```

2. Update the [Helm chart](./helm/values.yaml) with your custom configuration.

3. Install the chart.
    ```bash
    $ helm install ./helm/ibmcloudappid --name ibmcloudappid
    ```

## Applying an authorization and authentication policy

An authentication or authorization policy is a set of conditions that must be met before a request can access a resource access. By defining an identity provider's service configuration and an access policy that outlines when a particular access control flow should be used, you can control access to any resource in your service mesh.

>> To see example CRD's, check out the [samples directory](./samples/crds).


### Defining a Configuration

Depending on whether you're protecting frontend or backend applications, create a policy configuration with one of the following options.

* For backend applications: The OAuth 2.0 Bearer token spec defines a pattern for protecting APIs by using [JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7519.html). Using the following configuration as an example, define a `JwtConfig` CRD that contains the public key resource, which is used to validate token signatures.

    ```
    apiVersion: "security.cloud.ibm.com/v1"
    kind: JwtConfig
    metadata:
        name: samplejwtpolicy
        namespace: sample-app
    spec:
        jwksUrl: https://us-south.appid.cloud.ibm.com/oauth/v4/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/publickeys
    ```

* For frontend applications: Browser based applications that require user authentication can be configured to use the OIDC / OAuth 2.0 authentication flow. To define an `OidcConfig` CRD containing the client used to facilitate the authentication flow with the Identity provider, use the following example as a guide.

    ```helmyaml
    kind: OidcConfig
    metadata:
        name: oidc-provider-config
        namespace: sample-namespace
    spec:
        discoveryUrl: https://us-south.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/oidc-discovery/.well-known
        clientId: 1234-abcd-efgh-4567
        clientSecret: randomlyGeneratedClientSecret
        clientSecretRef:
            name: <name-of-my-kube-secret>
            key: <key-in-my-kube-secret>
    ```

    | Field   | Type | Required |      Description      |
    |----------|:-------------:|:-------------:| :---: |
    | `discoveryUrl` | string | yes| A well-known endpoint that contains a JSON document of OIDC/OAuth 2.0 configuration information. |
    | `clientId` | string | yes | An identifier for the client that is used for authentication. |
    | `clientSecret` | string | *no|  A plain text secret that is used to authenticate the client. If not provided, a `clientSecretRef` must exist. |
    | `clientSecretRef` | object | no | A reference secret that is used to authenticate the client. This can be used in place of the `clientSecret`. |
    | `clientSecretRef.name` | string |yes | The name of the Kubernetes Secret that contains the `clientSecret`. |
    | `clientSecretRef.key` | string | yes | The field within the Kubernetes Secret that contains the `clientSecret`. |


### Register application endpoints

Register application endpoints within a `Policy` CRD to validate incoming requests and enforce authentication rules. Each `Policy` applies exclusively to the Kubernetes namespace in which the object lives and can specify the services, paths, and methods that you want to protect.

    ```helmyaml
    kind: Policy
    metadata:
        name: policy-1
        namespace: sample-namespace
    spec:
        targets:
        - service: svc-service-name-123
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

    | Service Object | Type | Required | Description   |
    |----------------|:----:|:--------:| :-----------: |
    | `service` | string | yes | The name of Kubernetes service in the Policy namespace that you want to protect. |
    | `paths` | array | yes | A list of path objects that define the endpoints that you want to protect. If left empty, all paths are protected. |

    | Path Object    | Type | Required | Description   |
    |----------------|:----:|:--------:| :-----------: |
    | `exact or prefix` | string | yes | The path that you want to apply the policies on. Options include `exact` and `prefix`. `exact` matches the provides endpoints exactly with the last `/` trimmed. `prefix` matches the endpoints that begin with the route prefix that you provide. |
    | `method` | enum | no | The HTTP method protected. Valid options ALL, GET, PUT, POST, DELETE, PATCH - Defaults to ALL:  |
    | `policies` | array | no | The OIDC/JWT policies that you want to apply.  |

    | Policy Object  | Type | Required | Description   |
    |----------------|:----:|:--------:| :-----------: |
    | `type` | enum | yes | The type of OIDC policy. Options include: `jwt` or `oidc`. |
    | `config` | string | yes | The name of the provider config that you want to use. |



## Cleanup

To remove the Adapter and all of the associated CRDs, you can delete the Helm chart and the associated signing + encrpytion keys.

```bash
$ helm delete --purge ibmcloudappid
$ kubectl delete secret ibmcloudappid-keys -n istio-system
```

## FAQ and troubleshooting

If you encounter an issue while working with the App ID Adapter, consider the following FAQ's and troubleshooting techniques. For more help, You can ask questions through a forum or open a support ticket. When you are using the forums to ask a question, tag your question so that it is seen by the App ID development team.

  * If you have technical questions about App ID, post your question on <a href="https://stackoverflow.com/" target="_blank">Stack Overflow <img src="../../icons/launch-glyph.svg" alt="External link icon"></a> and tag your question with "ibm-appid".
  * For questions about the service and getting started instructions, use the <a href="https://developer.ibm.com/" target="_blank">dW Answers <img src="../../icons/launch-glyph.svg" alt="External link icon"></a> forum. Include the `appid` tag.

For more information about getting support, see [how do I get the support that I need](/docs/get-support?topic=get-support-getting-customer-support#getting-customer-support).


### Troubleshooting: Logging

By default, logs are styled as JSON and provided at an `info` visbility level to provide for ease of integration with external logging systems. To update the logging configuration, you can use the Helm chart. Supported logging levels include range [-1, 7] as shown in Zapcore. For more information about the levels, see the [Zapcore documentation](https://godoc.org/go.uber.org/zap/zapcore#Level).

>> **Note:** When you're manually viewing JSON logs, you might want to tail the logs and "pretty print" them by using [jq](https://brewinstall.org/install-jq-on-mac-with-brew/).

**Adapter**

To see the Adapter logs, you can use `kubectl` or access the pod from the `ibmcloudappid` pod from the Kubernetes console.

```bash
$ export adapter_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=ibmcloudappid -o jsonpath='{.items[0].metadata.name}')
$ adapter_logs | jq
```

**Mixer**

If the Adapter does not appear to recieve requests, check the Mixer logs to ensure that it is successfully connected to the Adapter.

```bash
$ export mixer_logs=kubectl -n istio-system logs -f $(kubectl -n istio-system get pods -lapp=telemetry -o jsonpath='{.items[0].metadata.name}') -c mixer
$ mixer_logs
```

## License

This package contains code licensed under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 and may also view the License in the LICENSE file within this package.

[img-ibmcloud-powered]: https://img.shields.io/badge/ibm%20cloud-powered-blue.svg
[url-ibmcloud]: https://www.ibm.com/cloud/
[img-license]: https://img.shields.io/npm/l/ibmcloud-appid.svg
[img-version]: https://img.shields.io/npm/v/ibmcloud-appid.svg

[img-github-watchers]: https://img.shields.io/github/watchers/ibm-cloud-security/app-identity-and-access-adapter.svg?style=social&label=Watch
[url-github-watchers]: https://github.com/ibm-cloud-security/app-identity-and-access-adapter/watchers
[img-github-stars]: https://img.shields.io/github/stars/ibm-cloud-security/app-identity-and-access-adapter.svg?style=social&label=Star
[url-github-stars]: https://github.com/ibm-cloud-security/app-identity-and-access-adapter/stargazers
[img-github-forks]: https://img.shields.io/github/forks/ibm-cloud-security/app-identity-and-access-adapter.svg?style=social&label=Fork
[url-github-forks]: https://github.com/ibm-cloud-security/app-identity-and-access-adapter/network

[img-travis-master]: https://travis-ci.org/ibm-cloud-security/app-identity-and-access-adapter.svg?branch=development
[url-travis-master]: https://travis-ci.org/ibm-cloud-security/app-identity-and-access-adapter

[img-coveralls-master]: https://coveralls.io/repos/github/ibm-cloud-security/app-identity-and-access-adapter/badge.svg
[url-coveralls-master]: https://coveralls.io/github/ibm-cloud-security/app-identity-and-access-adapter
[img-codacy]: https://api.codacy.com/project/badge/Grade/2dd243b5b9f64431bf03bf0a9a470833?branch=master
[url-codacy]: https://app.codacy.com/app/ibm-cloud-security/app-identity-and-access-adapter?utm_source=github.com&utm_medium=referral&utm_content=ibm-cloud-security/app-identity-and-access-adapter&utm_campaign=Badge_Grade_Dashboard

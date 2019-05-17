// Package handler is responsible for monitoring and maintaining authn/z policies
package handler

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store"

	"istio.io/pkg/log"
)

// PolicyHandler is responsible for storing and managing policy/client data
type PolicyHandler interface {
	HandleAddUpdateEvent(obj interface{})
	HandleDeleteEvent(obj interface{})
}

// CrdHandler is responsible for storing and managing policy/client data
type CrdHandler struct {
	store store.PolicyStore
}

////////////////// constructor //////////////////

// New creates a PolicyManager
func New(store store.PolicyStore) PolicyHandler {
	return &CrdHandler{
		store: store,
	}
}

////////////////// interface //////////////////

// HandleAddUpdateEvent updates the store after a CRD has been added
func (c *CrdHandler) HandleAddUpdateEvent(obj interface{}) {
	switch crd := obj.(type) {
	case *v1.JwtPolicy:
		log.Debugf("Create/Update JwtPolicy : ID: %s", crd.ObjectMeta.UID)

		// If we already are tracking this authentication server, skip
		if c.store.GetKeySet(crd.Spec.JwksURL) == nil {
			c.store.AddKeySet(crd.Spec.JwksURL, keyset.New(crd.Spec.JwksURL, nil))
		}

		mappingKey := crd.ObjectMeta.Namespace + "/" + crd.ObjectMeta.Name
		policyEndpoints := parseTarget(crd.Spec.Target, crd.ObjectMeta.Namespace)
		if c.store.GetPolicyMapping(mappingKey) != nil {
			// for update delete the old object mappings
			log.Debugf("Update event for Policy. Calling Delete to remove the old mappings")
			c.HandleDeleteEvent(policy.CrdKey{Id: mappingKey})
		}
		c.store.AddPolicyMapping(mappingKey, &policy.PolicyMapping{Type: policy.JWT, Endpoints: policyEndpoints, Spec: crd.Spec})
		for _, ep := range policyEndpoints {
			c.store.SetApiPolicy(ep, crd.Spec)
		}
		log.Debugf("JwtPolicy created/updated : ID %s", crd.ObjectMeta.UID)
	case *v1.OidcPolicy:
		log.Debugf("OIDC Policy created : ID: %s", crd.ObjectMeta.UID)
		policyEndpoints := parseTarget(crd.Spec.Target, crd.ObjectMeta.Namespace)
		for _, ep := range policyEndpoints {
			c.store.SetWebPolicy(ep, crd.Spec)
		}
		log.Infof("OIDC Policy created : ID %s", crd.ObjectMeta.UID)
	case *v1.OidcClient:
		log.Debugf("Creating OIDC Client : ID: %s", crd.ObjectMeta.UID)

		// If we already are tracking this authentication server, skip
		authorizationServer := c.store.GetAuthServer(crd.Spec.DiscoveryUrl)
		if authorizationServer == nil {
			authorizationServer = authserver.New(crd.Spec.DiscoveryUrl)
			c.store.AddAuthServer(crd.Spec.DiscoveryUrl, authorizationServer)
		}

		// If the server synced successfully, we can configure the JWKs instance
		// Otherwise, it will be configured lazily
		if jwksURL := authorizationServer.JwksEndpoint(); jwksURL != "" {
			// If we already track the JWKs for this OAuth 2.0 server, we can share the original instance
			if jwks := c.store.GetKeySet(jwksURL); jwks != nil {
				authorizationServer.SetKeySet(jwks)
			} else {
				jwks = keyset.New(jwksURL, nil)
				authorizationServer.SetKeySet(jwks)
				c.store.AddKeySet(jwksURL, jwks)
			}
		}

		// Create and store OIDC Client
		oidcClient := client.New(crd.Spec, authorizationServer)
		c.store.AddClient(oidcClient.Name(), oidcClient)

		log.Infof("OIDC Client created : ID %s", crd.ObjectMeta.UID)
	default:
		log.Errorf("Could not create object. Unknown type : %f", crd)
	}
}

// HandleDeleteEvent updates the store after a CRD has been deleted
func (c *CrdHandler) HandleDeleteEvent(obj interface{}) {
	crdKey, ok := obj.(policy.CrdKey)
	if !ok {
		log.Errorf("Expected to receive CrdKey")
		return
	}

	mapping := c.store.GetPolicyMapping(crdKey.Id)
	if mapping == nil {
		log.Errorf("CRD was not found.") // happens with OIDC policies at the moment
		return
	}

	switch mapping.Type {
	case policy.JWT:
		log.Debugf("Deleting Object of type : %d", policy.JWT)
		for _, ep := range mapping.Endpoints {
			c.store.DeleteApiPolicy(ep, mapping.Spec)
		}
		c.store.DeletePolicyMapping(crdKey.Id)
		log.Debug("Delete Complete")
	default:
		log.Errorf("Could not delete object. Unknown type : %d", mapping.Type)
	}
}

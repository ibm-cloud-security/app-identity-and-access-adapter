// Package handler is responsible for monitoring and maintaining authn/z policies
package handler

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store"
	"go.uber.org/zap"
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
		zap.L().Debug("Create/Update JwtPolicy", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))

		// If we already are tracking this authentication server, skip
		if c.store.GetKeySet(crd.Spec.JwksURL) == nil {
			c.store.AddKeySet(crd.Spec.JwksURL, keyset.New(crd.Spec.JwksURL, nil))
		}

		mappingKey := generatePolicyMappingKey(policy.JWT, crd.ObjectMeta.Namespace, crd.ObjectMeta.Name)
		zap.S().Debug("crdKey : %s", "mappingKey", mappingKey)
		policyEndpoints := parseTarget(crd.Spec.Target, crd.ObjectMeta.Namespace)
		if c.store.GetPolicyMapping(mappingKey) != nil {
			// for update delete the old object mappings
			zap.L().Debug("Update event for Policy. Calling Delete to remove the old mappings")
			c.HandleDeleteEvent(policy.CrdKey{Id: mappingKey})
		}
		c.store.AddPolicyMapping(mappingKey, &policy.PolicyMapping{Type: policy.JWT, Endpoints: policyEndpoints, Spec: crd.Spec})
		for _, ep := range policyEndpoints {
			//TODO: once we define how rules are going to be, map rules to actions here
			c.store.SetApiPolicy(ep, policy.Action{Type: policy.JWT, KeySet: c.store.GetKeySet(crd.Spec.JwksURL), Client: nil, Rules: nil})
		}
		zap.L().Info("JwtPolicy created/updated", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))
	case *v1.OidcPolicy:
		zap.L().Debug("OIDCPolicy created/updated", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))
		mappingKey := generatePolicyMappingKey(policy.OIDC, crd.ObjectMeta.Namespace, crd.ObjectMeta.Name)
		policyEndpoints := parseTarget(crd.Spec.Target, crd.ObjectMeta.Namespace)

		if c.store.GetPolicyMapping(mappingKey) != nil {
			// for update delete the old object mappings
			zap.L().Debug("Update event for Policy. Calling Delete to remove the old mappings")
			c.HandleDeleteEvent(policy.CrdKey{Id: mappingKey})
		}

		c.store.AddPolicyMapping(mappingKey, &policy.PolicyMapping{Type: policy.OIDC, Endpoints: policyEndpoints, Spec: crd.Spec})
		for _, ep := range policyEndpoints {
			c.store.SetWebPolicy(ep, policy.Action{
				Type:       policy.OIDC,
				KeySet:     nil,
				Client:     c.store.GetClient(crd.Spec.ClientName),
				ClientName: crd.Spec.ClientName,
				Rules:      nil})
		}
		zap.L().Info("OIDCPolicy created", zap.String("ID", string(crd.ObjectMeta.UID)))
	case *v1.OidcClient:
		zap.L().Debug("OIDCClient created/updated", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))

		// If we already are tracking this authentication server, skip
		authorizationServer := c.store.GetAuthServer(crd.Spec.DiscoveryURL)
		if authorizationServer == nil {
			authorizationServer = authserver.New(crd.Spec.DiscoveryURL)
			c.store.AddAuthServer(crd.Spec.DiscoveryURL, authorizationServer)
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

		zap.L().Info("OIDCClient created", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))
	default:
		zap.S().Warn("Could not create object. Unknown type: %f", crd)
	}
}

// HandleDeleteEvent updates the store after a CRD has been deleted
func (c *CrdHandler) HandleDeleteEvent(obj interface{}) {
	crdKey, ok := obj.(policy.CrdKey)
	if !ok {
		zap.L().Warn("Expected to receive CrdKey from Kubernetes informer")
		return
	}
	zap.S().Debugf("crdKey : %s", crdKey.Id)
	mapping := c.store.GetPolicyMapping(crdKey.Id)
	if mapping == nil {
		zap.L().Warn("CRD was not found") // happens with OIDC policies at the moment
		return
	}

	switch mapping.Type {
	case policy.JWT:
		zap.L().Debug("Deleting JWT Policy", zap.String("type", "JWT"), zap.String("id", crdKey.Id))
		for _, ep := range mapping.Endpoints {
			c.store.DeleteApiPolicy(ep, mapping.Spec)
		}
		c.store.DeletePolicyMapping(crdKey.Id)
		zap.L().Info("Successfully deleted JWT Policy", zap.String("type", "JWT"), zap.String("id", crdKey.Id))
	default:
		zap.L().Warn("Unknown policy type")
	}
}

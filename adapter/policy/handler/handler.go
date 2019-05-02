// Package handler is responsible for monitoring and maintaining authn/z policies
package handler

import (
	"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"
	"ibmcloudappid/adapter/policy/store"

	"istio.io/istio/pkg/log"
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
		if c.store.GetAuthServer(crd.Spec.JwksURL) == nil {
			c.store.AddAuthServer(crd.Spec.JwksURL, authserver.New(crd.Spec.JwksURL))
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
		log.Debugf("OidcPolicy created : ID: %s", crd.ObjectMeta.UID)
		log.Infof("OidcPolicy created : ID %s", crd.ObjectMeta.UID)
	case *v1.OidcClient:
		log.Debugf("Creating OidcClient : ID: %s", crd.ObjectMeta.UID)
		log.Infof("OidcClient created : ID %s", crd.ObjectMeta.UID)
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

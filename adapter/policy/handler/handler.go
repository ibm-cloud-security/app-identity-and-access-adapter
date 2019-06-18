// Package handler is responsible for monitoring and maintaining authn/z policies
package handler

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"

	// "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	// "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	// "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	policy2 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

// PolicyHandler is responsible for storing and managing policy/client data
type PolicyHandler interface {
	HandleAddUpdateEvent(obj interface{})
	HandleDeleteEvent(obj interface{})
}

// CrdHandler is responsible for storing and managing policy/client data
type CrdHandler struct {
	store      policy2.PolicyStore
	kubeClient kubernetes.Interface
}

////////////////// constructor //////////////////

// New creates a PolicyManager
func New(store policy2.PolicyStore, kubeClient kubernetes.Interface) PolicyHandler {
	return &CrdHandler{
		store:      store,
		kubeClient: kubeClient,
	}
}

////////////////// interface //////////////////

// HandleAddUpdateEvent updates the store after a CRD has been added
func (c *CrdHandler) HandleAddUpdateEvent(obj interface{}) {
	switch crd := obj.(type) {
	case *v1.JwtConfig:
		zap.L().Info("Create/Update JwtPolicy", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))
		crd.Spec.ClientName = crd.ObjectMeta.Namespace + "." + crd.ObjectMeta.Name
		if c.store.GetKeySet(crd.Spec.ClientName) != nil {
			zap.L().Info("Update JwtPolicy", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))
		}
		c.store.AddKeySet(crd.Spec.ClientName, keyset.New(crd.Spec.JwksURL, nil))
		zap.L().Info("JwtPolicy created/updated", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.ObjectMeta.Name), zap.String("namespace", crd.ObjectMeta.Namespace))
	case *v1.Policy:
		zap.L().Debug("Create/Update Policy", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.ObjectMeta.Name), zap.String("namespace", crd.ObjectMeta.Namespace))
		parsedPolicies := parseTarget(crd.Spec.Target, crd.ObjectMeta.Namespace)
		for _, policies := range parsedPolicies {
			c.store.SetPolicies(policies.Endpoint, policies.Actions)
		}
		zap.L().Info("Policy created/updated", zap.String("ID", string(crd.ObjectMeta.UID)))
	case *v1.OidcConfig:
		zap.L().Debug("Create/Update OidcConfig", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("clientSecret", crd.Spec.ClientSecret), zap.String("name", crd.ObjectMeta.Name), zap.String("namespace", crd.ObjectMeta.Namespace))
		crd.Spec.ClientName = crd.ObjectMeta.Namespace + "." + crd.ObjectMeta.Name
		authorizationServer := authserver.New(crd.Spec.DiscoveryURL)
		keySets := keyset.New(authorizationServer.JwksEndpoint(), nil)
		authorizationServer.SetKeySet(keySets)
		if secret := c.getClientSecret(crd); secret != "" {
			crd.Spec.ClientSecret = secret
			// Create and store OIDC Client
			oidcClient := client.New(crd.Spec, authorizationServer)
			c.store.AddClient(oidcClient.Name(), oidcClient)
			zap.L().Info("OidcConfig created/updated", zap.String("ID", string(crd.ObjectMeta.UID)), zap.String("name", crd.Name), zap.String("namespace", crd.Namespace))
		} else {
			zap.L().Warn("Failed to create object: client secret is invalid")
		}
	default:
		zap.S().Warn("Could not create object. Unknown type: %f", crd)
	}
}

func (c *CrdHandler) getClientSecret(crd *v1.OidcConfig) string {
	//Return kube secret from reference if present, else try clientSecret
	if crd.Spec.ClientSecretRef.Name != "" && crd.Spec.ClientSecretRef.Key != "" {
		secret, err := GetKubeSecret(c.kubeClient, crd.ObjectMeta.Namespace, crd.Spec.ClientSecretRef)
		if err != nil || string(secret.Data[crd.Spec.ClientSecretRef.Key]) == "" {
			zap.S().Warn("Failed to get kube secret: ", err)
			return crd.Spec.ClientSecret
		} else {
			return string(secret.Data[crd.Spec.ClientSecretRef.Key])
		}
	} else if crd.Spec.ClientSecret != "" {
		return crd.Spec.ClientSecret
	}
	return ""
}

// HandleDeleteEvent updates the store after a CRD has been deleted
func (c *CrdHandler) HandleDeleteEvent(obj interface{}) {
	crdKey, ok := obj.(policy.CrdKey)
	if !ok {
		zap.L().Warn("Expected to receive CrdKey from Kubernetes informer")
		return
	}
	// TODO: Temporary fix for policy deletion. Needs support for OIDC clients. This should come from the controller `policy.CrdKey` not constructed blindly here
	zap.S().Debugf("crdKey : %s", crdKey.Id)
	mapping := c.store.GetPolicyMapping(policy.JWT.String() + "/" + crdKey.Id)
	if mapping == nil {
		mapping = c.store.GetPolicyMapping(policy.OIDC.String() + "/" + crdKey.Id)
		if mapping == nil {
			zap.L().Warn("CRD was not found")
			return
		}
	}
	/*
	switch mapping.Type {
	case policy.JWT:
		zap.L().Debug("Deleting JWT Policy", zap.String("type", "JWT"), zap.String("id", crdKey.Id))
		for _, ep := range mapping.Endpoints {
			c.store.DeleteApiPolicy(ep, mapping.Spec)
		}
		c.store.DeletePolicyMapping(crdKey.Id)
		zap.L().Info("Successfully deleted JWT Policy", zap.String("type", "JWT"), zap.String("id", crdKey.Id))
	case policy.OIDC:
		zap.L().Debug("Deleting OIDC Policy", zap.String("type", "JWT"), zap.String("id", crdKey.Id))
		for _, ep := range mapping.Endpoints {
			c.store.DeleteWebPolicy(ep, mapping.Spec)
		}
		c.store.DeletePolicyMapping(crdKey.Id)
		zap.L().Info("Successfully deleted OIDC Policy", zap.String("type", "OIDC"), zap.String("id", crdKey.Id))
	default:
		zap.L().Warn("Unknown policy type")
	}

	*/
}

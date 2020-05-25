package crdeventhandler

import (
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/client"
	v1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
	storepolicy "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy/store/policy"
)

type AddUpdateEventHandler interface {
	HandleAddUpdateEvent()
}

type JwtConfigAddEventHandler struct {
	Obj   *v1.JwtConfig
	Store storepolicy.PolicyStore
}

type OidcConfigAddEventHandler struct {
	Obj        *v1.OidcConfig
	KubeClient kubernetes.Interface
	Store      storepolicy.PolicyStore
}

type PolicyAddEventHandler struct {
	Obj   *v1.Policy
	Store storepolicy.PolicyStore
}

func (e *JwtConfigAddEventHandler) HandleAddUpdateEvent() {
	zap.L().Info("Create/Update JwtConfig", zap.String("ID", string(e.Obj.ObjectMeta.UID)), zap.String("name", e.Obj.Name), zap.String("namespace", e.Obj.Namespace))
	e.Obj.Spec.ClientName = e.Obj.ObjectMeta.Namespace + "/" + e.Obj.ObjectMeta.Name
	e.Store.AddKeySet(e.Obj.Spec.ClientName, keyset.New(e.Obj.Spec.JwksURL, nil))
	zap.L().Info("JwtConfig created/updated", zap.String("ID", string(e.Obj.ObjectMeta.UID)), zap.String("name", e.Obj.ObjectMeta.Name), zap.String("namespace", e.Obj.ObjectMeta.Namespace))
}

func (e *OidcConfigAddEventHandler) HandleAddUpdateEvent() {
	zap.L().Debug("Create/Update OidcConfig", zap.String("ID", string(e.Obj.ObjectMeta.UID)), zap.String("name", e.Obj.ObjectMeta.Name), zap.String("namespace", e.Obj.ObjectMeta.Namespace))
	e.Obj.Spec.ClientName = e.Obj.ObjectMeta.Namespace + "/" + e.Obj.ObjectMeta.Name
	if e.Obj.Spec.AuthMethod == "" {
		e.Obj.Spec.AuthMethod = "client_secret_basic"
	}

	if len(e.Obj.Spec.DiscoveryURL) == 0 {
		zap.L().Warn("Empty discoveryURL in OidcConfig", zap.String("name", e.Obj.ObjectMeta.Name), zap.String("namespace", e.Obj.ObjectMeta.Namespace))
	}

	authorizationServer := authserver.New(e.Obj.Spec.DiscoveryURL)
	keySets := keyset.New(authorizationServer.JwksEndpoint(), nil)
	authorizationServer.SetKeySet(keySets)
	e.Obj.Spec.ClientSecret = GetClientSecret(e.Obj, e.KubeClient)
	// Create and store OIDC Client
	oidcClient := client.New(e.Obj.Spec, authorizationServer)
	e.Store.AddClient(oidcClient.Name(), oidcClient)
	zap.L().Info("OidcConfig created/updated", zap.String("ID", string(e.Obj.ObjectMeta.UID)), zap.String("name", e.Obj.Name), zap.String("namespace", e.Obj.Namespace))
}

func (e *PolicyAddEventHandler) HandleAddUpdateEvent() {
	zap.L().Debug("Create/Update Policy", zap.String("ID", string(e.Obj.ObjectMeta.UID)), zap.String("name", e.Obj.ObjectMeta.Name), zap.String("namespace", e.Obj.ObjectMeta.Namespace))
	mappingId := e.Obj.ObjectMeta.Namespace + "/" + e.Obj.ObjectMeta.Name
	parsedPolicies := ParseTarget(e.Obj.Spec.Target, e.Obj.ObjectMeta.Namespace)
	for _, policies := range parsedPolicies {
		zap.S().Debug("Adding policy for endpoint", policies.Endpoint)
		e.Store.SetPolicies(policies.Endpoint, policy.RoutePolicy{PolicyReference: mappingId, Actions: policies.Actions})
	}
	e.Store.AddPolicyMapping(mappingId, parsedPolicies)
	zap.L().Info("Policy created/updated", zap.String("ID", string(e.Obj.ObjectMeta.UID)))
}

func GetClientSecret(crd *v1.OidcConfig, kubeClient kubernetes.Interface) string {
	// Return kube secret from reference if present, else try clientSecret
	if crd.Spec.ClientSecretRef.Name != "" && crd.Spec.ClientSecretRef.Key != "" {
		secret, err := GetKubeSecret(kubeClient, crd.ObjectMeta.Namespace, crd.Spec.ClientSecretRef)
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

func GetAddEventHandler(obj interface{}, store storepolicy.PolicyStore, kubeClient kubernetes.Interface) AddUpdateEventHandler {
	switch crd := obj.(type) {
	case *v1.JwtConfig:
		return &JwtConfigAddEventHandler{
			Obj:   crd,
			Store: store,
		}
	case *v1.OidcConfig:
		return &OidcConfigAddEventHandler{
			Obj:        crd,
			Store:      store,
			KubeClient: kubeClient,
		}
	case *v1.Policy:
		return &PolicyAddEventHandler{
			Obj:   crd,
			Store: store,
		}
	default:
		return nil
	}
}

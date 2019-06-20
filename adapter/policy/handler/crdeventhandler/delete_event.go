package crdeventhandler

import (
	"go.uber.org/zap"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	storepolicy "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
)

type DeleteEventHandler interface {
	HandleDeleteEvent()
}

type JwtConfigDeleteEventHandler struct {
	Key string
	Store storepolicy.PolicyStore
}

type OidcConfigDeleteEventHandler struct {
	Key string
	Store storepolicy.PolicyStore
}

type PolicyDeleteEventHandler struct {
	Key string
	Store storepolicy.PolicyStore
}

func (e *JwtConfigDeleteEventHandler) HandleDeleteEvent() {
	e.Store.DeleteKeySet(e.Key)
}

func (e *OidcConfigDeleteEventHandler) HandleDeleteEvent() {
	e.Store.DeleteClient(e.Key)
}

func (e *PolicyDeleteEventHandler) HandleDeleteEvent() {
	parsedPolicies := e.Store.GetPolicyMapping(e.Key)
	for _, policies := range parsedPolicies {
		zap.S().Debug("Getting policy for endpoint", policies.Endpoint)
		storedPolicy := e.Store.GetPolicies(policies.Endpoint)
		if storedPolicy.PolicyReference == e.Key {
			e.Store.SetPolicies(policies.Endpoint, policy.NewRoutePolicy())
		}
	}
	// remove entry from policyMapping
	e.Store.DeletePolicyMapping(e.Key)
	zap.S().Debug("Delete policy completed")
}

func GetDeleteEventHandler(crd policy.CrdKey, store storepolicy.PolicyStore) DeleteEventHandler {
	switch crd.CrdType {
	case v1.JWTCONFIG:
		return &JwtConfigDeleteEventHandler{
			Key:   crd.Id,
			Store: store,
		}
	case v1.OIDCCONFIG:
		return &OidcConfigDeleteEventHandler{
			Key:   crd.Id,
			Store: store,
		}
	case v1.POLICY:
		return &PolicyDeleteEventHandler{
			Key:   crd.Id,
			Store: store,
		}
	default:
		zap.S().Warn("Could not delete object. Unknown type: %f", crd)
		return nil
	}
}

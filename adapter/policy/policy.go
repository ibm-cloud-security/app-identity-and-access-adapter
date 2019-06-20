package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
)

// Type represents a policy types (WEB/API)
type Type int

const (
	// JWT policy types specifies requests protected by API strategy
	JWT Type = iota
	// OIDC policy types specifies requests protected by WEB strategy
	OIDC
	// NONE policy specifies requests without protection
	NONE
)

// Endpoint captures a request endpoint
type Endpoint struct {
	Service Service
	// Path holds a url path string
	Path string
	// Method holds an HTTP Method
	Method Method
}

// CrdKey represents a CustomResourceDefinition ID
type CrdKey struct {
	// ID if of the form "namespace/crd_name"
	ID string
	// CrdType is the type of CRD
	CrdType v1.CrdType
}

// Mapping captures information of created endpoints by policy
type Mapping struct {
	Actions  []v1.PathPolicy
	Endpoint Endpoint
}

// RoutePolicy captures information of created endpoints by policy
type RoutePolicy struct {
	PolicyReference string
	Actions         []v1.PathPolicy
}

// NewRoutePolicy creates a new RoutePolicy
func NewRoutePolicy() RoutePolicy {
	return RoutePolicy{
		Actions: make([]v1.PathPolicy, 0),
	}
}

// NewPolicyMapping creates a new Mapping object
func NewPolicyMapping(service Endpoint, actions []v1.PathPolicy) Mapping {
	return Mapping{
		Endpoint: service,
		Actions:  actions,
	}
}

var typeNames = [...]string{"JWT", "OIDC", "NONE"}

// String returns a prettified string of the given Type
func (t Type) String() string {
	return typeNames[t]
}

// NewType creates a new policy Type
func NewType(t string) Type {
	switch t {
	case "jwt":
		return JWT
	case "oidc":
		return OIDC
	default:
		return NONE
	}
}

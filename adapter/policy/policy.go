package policy

import (
	v1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
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
	Id      string
	CrdType v1.CrdType
}

// PolicyMapping captures information of created endpoints by policy
type PolicyMapping struct {
	Actions  []v1.PathPolicy
	Endpoint Endpoint
}

type RoutePolicy struct {
	PolicyReference string
	Actions         []v1.PathPolicy
}

func NewRoutePolicy() RoutePolicy {
	return RoutePolicy{
		PolicyReference: "",
		Actions:         make([]v1.PathPolicy, 0),
	}
}

// New creates a new ParsedPolicies
func NewPolicyMapping(service Endpoint, actions []v1.PathPolicy) PolicyMapping {
	return PolicyMapping{
		Endpoint: service,
		Actions:  actions,
	}
}

var typeNames = [...]string{"JWT", "OIDC", "NONE"}

func (t Type) String() string {
	return typeNames[t]
}

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

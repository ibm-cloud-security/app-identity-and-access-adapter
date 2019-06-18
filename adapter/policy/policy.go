package policy

import "go.uber.org/zap"

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
	Id string
}

// Rule represents a policy validation rule
type Rule struct {
	Key   string
	Value string
}

// PolicyMapping captures information of created endpoints by policy
type PolicyMapping struct {
	Type      Type
	Endpoints []Endpoint
	Spec      interface{}
}

var typeNames = [...]string{"JWT", "OIDC", "NONE"}

func (t Type) String() string {
	return typeNames[t]
}

func NewType(t string) Type {
	zap.S().Info("Type: ", t)
	switch t {
	case "jwt":
		return JWT
	case "oidc":
		return OIDC
	default:
		return NONE
	}
}

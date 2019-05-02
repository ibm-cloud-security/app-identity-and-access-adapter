package policy

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
	Namespace, Service, Path, Method string
}

// PolicyMapping captures information of created endpoints by policy
type PolicyMapping struct {
	Type      Type
	Endpoints []Endpoint
	Spec      interface{}
}

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
	Service Service
	Path string
	//Method Method
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

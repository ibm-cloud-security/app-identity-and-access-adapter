package policy

// Type represents a policy types (WEB/API)
type Type int

const (
	// API policy types specifies requests protected by API strategy
	API Type = iota
	// WEB policy types specifies requests protected by WEB strategy
	WEB
)

// Policy encasulates an authn/z policy definition
type Policy struct {
	clientName string
	dest       string
	Type       Type `json:"type"`
}

// New creates a new policy
func New() Policy {
	return Policy{}
}

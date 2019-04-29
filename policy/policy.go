package policy

// Type represents a policy types (WEB/API)
type Type int

const (
	// API policy types specifies requests protected by API strategy
	API Type = iota
	// WEB policy types specifies requests protected by WEB strategy
	WEB
	// NONE policy specifies requests without protection
	NONE
)

// Policy encasulates an authn/z policy definition
type Policy struct {
	ClientName string
	Dest       string
	Type       Type `json:"type"`
}

// New creates a new policy
func New() Policy {
	return Policy{}
}

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

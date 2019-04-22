package client

// Type represents a client type (OIDC/OAuth2)
type Type int

const (
	// OAuth2 client
	OAuth2 Type = iota
	// OIDC client
	OIDC
)

// Client encasulates an authn/z client definition
type Client struct {
	Name         string
	ClientID     string
	Secret       string
	DiscoveryURL string
	Type         Type `json:"type"`
}

// New creates a new policy
func New() Client {
	return Client{}
}

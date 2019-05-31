package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
)

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type       Type
	KeySet     keyset.KeySet
	Client     client.Client
	ClientName string
	Rules      []Rule
}

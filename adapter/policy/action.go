package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
)

type Method int

const (
	ALL Method = iota
	GET
	PUT
	POST
	DELETE
)

func (m Method) String() string {
	return [...]string{"ALL", "GET", "PUT", "POST", "DELETE"}[m]
}

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type       Type
	KeySet     keyset.KeySet
	Client     client.Client
	ClientName string
	Rules      []Rule
}

type Actions struct {
	MethodActions map[Method][]Action
}

// New creates a new Actions
func NewActions() Actions {
	return Actions{
		MethodActions: make(map[Method][]Action),
	}
}
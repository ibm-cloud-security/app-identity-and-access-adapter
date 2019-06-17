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
	PATCH
)

func (m Method) String() string {
	return [...]string{"ALL", "GET", "PUT", "POST", "DELETE", "PATCH"}[m]
}

func NewMethod(method string) Method {
	switch method {
	case "ALL":
		return ALL
	case "GET":
		return GET
	case "PUT":
		return PUT
	case "POST":
		return POST
	case "DELETE":
		return DELETE
	case "PATCH":
		return PATCH
	default:
		return GET
	}
}

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type       Type
	KeySet     keyset.KeySet
	Client     client.Client
	ClientName string
	Rules      []Rule
}

type Actions = map[Method][]Action

// New creates a new Actions
func NewActions() Actions {
	return make(map[Method][]Action)
}

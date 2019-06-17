package policy

import (
	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
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
		return ALL
	}
}

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type       Type
	//KeySet     keyset.KeySet
	//Client     client.Client
	Config string
	RedirectUri string
	Rules      []Rule
}

type Actions = map[Method][]v1.PathPolicy

// New creates a new Actions
func NewActions() Actions {
	return make(map[Method][]v1.PathPolicy)
}

type ParsedPolicies struct {
	Actions []v1.PathPolicy
	Endpoint Endpoint
}

// New creates a new ParsedPolicies
func NewParsedPolicies(service Endpoint, actions []v1.PathPolicy) ParsedPolicies {
	return ParsedPolicies{
		Endpoint: service,
		Actions: actions,
	}
}
// Package enforcer is responsible for enforcing authn/z policy decision
package enforcer

type PolicyEnforcer interface {
	IsRrequired(string) bool
}

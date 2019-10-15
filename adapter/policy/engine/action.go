// Package engine is responsible for making policy decisions
package engine

import (
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/client"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
)

// Action encapsulates information needed to begin executing a policy
type Action struct {
	v1.PathPolicy
	KeySet     keyset.KeySet
	Client     client.Client
	Type       policy.Type
	Hosts []string
}

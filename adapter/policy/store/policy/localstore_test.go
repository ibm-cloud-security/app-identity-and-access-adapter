package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"
)

const (
	clientname   = "clientname"
	jwksurl      = "http://mockserver"
	endpoint      = "service/path"
	samplePolicy = "policy"
)

func getActions() policy.Actions{
	return policy.Actions{
		Actions: []policy.Action{
			{KeySet: &fake.KeySet{}, Type: policy.JWT},
		},
	}
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New())
}

func TestLocalStore_KeySet(t *testing.T) {
	store := New()
	assert.Nil(t, (&LocalStore{}).GetKeySet(jwksurl))
	assert.Nil(t, store.GetKeySet(jwksurl))
	store.AddKeySet(jwksurl, &fake.KeySet{})
	assert.NotNil(t, store.GetKeySet(jwksurl))
}

func TestLocalStore_Client(t *testing.T) {
	store := New()
	assert.Nil(t, (&LocalStore{}).GetClient(clientname))
	assert.Nil(t, store.GetClient(clientname))
	store.AddClient(clientname, &fake.Client{})
	assert.NotNil(t, store.GetClient(clientname))
}

func TestLocalStore_Policies(t *testing.T) {
	store := New()
	policies := policy.Actions{Actions:[]policy.Action{}}
	assert.Equal(t, store.GetPolicies(endpoint), policies)
	store.SetPolicies(endpoint, getActions())
	assert.Equal(t, store.GetPolicies(endpoint), getActions())
}

func TestLocalStore_PolicyMapping(t *testing.T) {
	store := &LocalStore{}
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
	store.AddPolicyMapping(samplePolicy, &policy.PolicyMapping{})
	assert.NotNil(t, store.GetPolicyMapping(samplePolicy))
	store.DeletePolicyMapping(samplePolicy)
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
}

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	policiesv1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeJwtPolicies implements JwtPolicyInterface
type FakeJwtPolicies struct {
	Fake *FakeAppidV1
	ns   string
}

var jwtpoliciesResource = schema.GroupVersionResource{Group: "appid.cloud.ibm.com", Version: "v1", Resource: "jwtpolicies"}

var jwtpoliciesKind = schema.GroupVersionKind{Group: "appid.cloud.ibm.com", Version: "v1", Kind: "JwtPolicy"}

// Get takes name of the jwtPolicy, and returns the corresponding jwtPolicy object, and an error if there is any.
func (c *FakeJwtPolicies) Get(name string, options v1.GetOptions) (result *policiesv1.JwtPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(jwtpoliciesResource, c.ns, name), &policiesv1.JwtPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.JwtPolicy), err
}

// List takes label and field selectors, and returns the list of JwtPolicies that match those selectors.
func (c *FakeJwtPolicies) List(opts v1.ListOptions) (result *policiesv1.JwtPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(jwtpoliciesResource, jwtpoliciesKind, c.ns, opts), &policiesv1.JwtPolicyList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &policiesv1.JwtPolicyList{ListMeta: obj.(*policiesv1.JwtPolicyList).ListMeta}
	for _, item := range obj.(*policiesv1.JwtPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested jwtPolicies.
func (c *FakeJwtPolicies) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(jwtpoliciesResource, c.ns, opts))

}

// Create takes the representation of a jwtPolicy and creates it.  Returns the server's representation of the jwtPolicy, and an error, if there is any.
func (c *FakeJwtPolicies) Create(jwtPolicy *policiesv1.JwtPolicy) (result *policiesv1.JwtPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(jwtpoliciesResource, c.ns, jwtPolicy), &policiesv1.JwtPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.JwtPolicy), err
}

// Update takes the representation of a jwtPolicy and updates it. Returns the server's representation of the jwtPolicy, and an error, if there is any.
func (c *FakeJwtPolicies) Update(jwtPolicy *policiesv1.JwtPolicy) (result *policiesv1.JwtPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(jwtpoliciesResource, c.ns, jwtPolicy), &policiesv1.JwtPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.JwtPolicy), err
}

// Delete takes name of the jwtPolicy and deletes it. Returns an error if one occurs.
func (c *FakeJwtPolicies) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(jwtpoliciesResource, c.ns, name), &policiesv1.JwtPolicy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeJwtPolicies) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(jwtpoliciesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &policiesv1.JwtPolicyList{})
	return err
}

// Patch applies the patch and returns the patched jwtPolicy.
func (c *FakeJwtPolicies) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *policiesv1.JwtPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(jwtpoliciesResource, c.ns, name, pt, data, subresources...), &policiesv1.JwtPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.JwtPolicy), err
}

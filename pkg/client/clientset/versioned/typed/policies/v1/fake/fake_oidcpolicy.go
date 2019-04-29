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
	policiesv1 "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/apis/policies/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeOidcPolicies implements OidcPolicyInterface
type FakeOidcPolicies struct {
	Fake *FakeAppidV1
	ns   string
}

var oidcpoliciesResource = schema.GroupVersionResource{Group: "appid.cloud.ibm.com", Version: "v1", Resource: "oidcpolicies"}

var oidcpoliciesKind = schema.GroupVersionKind{Group: "appid.cloud.ibm.com", Version: "v1", Kind: "OidcPolicy"}

// Get takes name of the oidcPolicy, and returns the corresponding oidcPolicy object, and an error if there is any.
func (c *FakeOidcPolicies) Get(name string, options v1.GetOptions) (result *policiesv1.OidcPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(oidcpoliciesResource, c.ns, name), &policiesv1.OidcPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcPolicy), err
}

// List takes label and field selectors, and returns the list of OidcPolicies that match those selectors.
func (c *FakeOidcPolicies) List(opts v1.ListOptions) (result *policiesv1.OidcPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(oidcpoliciesResource, oidcpoliciesKind, c.ns, opts), &policiesv1.OidcPolicyList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &policiesv1.OidcPolicyList{ListMeta: obj.(*policiesv1.OidcPolicyList).ListMeta}
	for _, item := range obj.(*policiesv1.OidcPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested oidcPolicies.
func (c *FakeOidcPolicies) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(oidcpoliciesResource, c.ns, opts))

}

// Create takes the representation of a oidcPolicy and creates it.  Returns the server's representation of the oidcPolicy, and an error, if there is any.
func (c *FakeOidcPolicies) Create(oidcPolicy *policiesv1.OidcPolicy) (result *policiesv1.OidcPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(oidcpoliciesResource, c.ns, oidcPolicy), &policiesv1.OidcPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcPolicy), err
}

// Update takes the representation of a oidcPolicy and updates it. Returns the server's representation of the oidcPolicy, and an error, if there is any.
func (c *FakeOidcPolicies) Update(oidcPolicy *policiesv1.OidcPolicy) (result *policiesv1.OidcPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(oidcpoliciesResource, c.ns, oidcPolicy), &policiesv1.OidcPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcPolicy), err
}

// Delete takes name of the oidcPolicy and deletes it. Returns an error if one occurs.
func (c *FakeOidcPolicies) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(oidcpoliciesResource, c.ns, name), &policiesv1.OidcPolicy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeOidcPolicies) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(oidcpoliciesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &policiesv1.OidcPolicyList{})
	return err
}

// Patch applies the patch and returns the patched oidcPolicy.
func (c *FakeOidcPolicies) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *policiesv1.OidcPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(oidcpoliciesResource, c.ns, name, pt, data, subresources...), &policiesv1.OidcPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcPolicy), err
}

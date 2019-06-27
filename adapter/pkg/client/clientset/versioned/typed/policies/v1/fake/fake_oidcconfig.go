/*
Copyright 2019 The Kubernetes Authors

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
	policiesv1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeOidcConfigs implements OidcConfigInterface
type FakeOidcConfigs struct {
	Fake *FakeAppidV1
	ns   string
}

var oidcconfigsResource = schema.GroupVersionResource{Group: "security.cloud.ibm.com", Version: "v1", Resource: "oidcconfigs"}

var oidcconfigsKind = schema.GroupVersionKind{Group: "security.cloud.ibm.com", Version: "v1", Kind: "OidcConfig"}

// Get takes name of the oidcConfig, and returns the corresponding oidcConfig object, and an error if there is any.
func (c *FakeOidcConfigs) Get(name string, options v1.GetOptions) (result *policiesv1.OidcConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(oidcconfigsResource, c.ns, name), &policiesv1.OidcConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcConfig), err
}

// List takes label and field selectors, and returns the list of OidcConfigs that match those selectors.
func (c *FakeOidcConfigs) List(opts v1.ListOptions) (result *policiesv1.OidcConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(oidcconfigsResource, oidcconfigsKind, c.ns, opts), &policiesv1.OidcConfigList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &policiesv1.OidcConfigList{ListMeta: obj.(*policiesv1.OidcConfigList).ListMeta}
	for _, item := range obj.(*policiesv1.OidcConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested oidcConfigs.
func (c *FakeOidcConfigs) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(oidcconfigsResource, c.ns, opts))

}

// Create takes the representation of a oidcConfig and creates it.  Returns the server's representation of the oidcConfig, and an error, if there is any.
func (c *FakeOidcConfigs) Create(oidcConfig *policiesv1.OidcConfig) (result *policiesv1.OidcConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(oidcconfigsResource, c.ns, oidcConfig), &policiesv1.OidcConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcConfig), err
}

// Update takes the representation of a oidcConfig and updates it. Returns the server's representation of the oidcConfig, and an error, if there is any.
func (c *FakeOidcConfigs) Update(oidcConfig *policiesv1.OidcConfig) (result *policiesv1.OidcConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(oidcconfigsResource, c.ns, oidcConfig), &policiesv1.OidcConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcConfig), err
}

// Delete takes name of the oidcConfig and deletes it. Returns an error if one occurs.
func (c *FakeOidcConfigs) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(oidcconfigsResource, c.ns, name), &policiesv1.OidcConfig{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeOidcConfigs) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(oidcconfigsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &policiesv1.OidcConfigList{})
	return err
}

// Patch applies the patch and returns the patched oidcConfig.
func (c *FakeOidcConfigs) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *policiesv1.OidcConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(oidcconfigsResource, c.ns, name, pt, data, subresources...), &policiesv1.OidcConfig{})

	if obj == nil {
		return nil, err
	}
	return obj.(*policiesv1.OidcConfig), err
}

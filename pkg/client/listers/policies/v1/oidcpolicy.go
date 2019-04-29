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

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/apis/policies/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// OidcPolicyLister helps list OidcPolicies.
type OidcPolicyLister interface {
	// List lists all OidcPolicies in the indexer.
	List(selector labels.Selector) (ret []*v1.OidcPolicy, err error)
	// OidcPolicies returns an object that can list and get OidcPolicies.
	OidcPolicies(namespace string) OidcPolicyNamespaceLister
	OidcPolicyListerExpansion
}

// oidcPolicyLister implements the OidcPolicyLister interface.
type oidcPolicyLister struct {
	indexer cache.Indexer
}

// NewOidcPolicyLister returns a new OidcPolicyLister.
func NewOidcPolicyLister(indexer cache.Indexer) OidcPolicyLister {
	return &oidcPolicyLister{indexer: indexer}
}

// List lists all OidcPolicies in the indexer.
func (s *oidcPolicyLister) List(selector labels.Selector) (ret []*v1.OidcPolicy, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.OidcPolicy))
	})
	return ret, err
}

// OidcPolicies returns an object that can list and get OidcPolicies.
func (s *oidcPolicyLister) OidcPolicies(namespace string) OidcPolicyNamespaceLister {
	return oidcPolicyNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// OidcPolicyNamespaceLister helps list and get OidcPolicies.
type OidcPolicyNamespaceLister interface {
	// List lists all OidcPolicies in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1.OidcPolicy, err error)
	// Get retrieves the OidcPolicy from the indexer for a given namespace and name.
	Get(name string) (*v1.OidcPolicy, error)
	OidcPolicyNamespaceListerExpansion
}

// oidcPolicyNamespaceLister implements the OidcPolicyNamespaceLister
// interface.
type oidcPolicyNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all OidcPolicies in the indexer for a given namespace.
func (s oidcPolicyNamespaceLister) List(selector labels.Selector) (ret []*v1.OidcPolicy, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.OidcPolicy))
	})
	return ret, err
}

// Get retrieves the OidcPolicy from the indexer for a given namespace and name.
func (s oidcPolicyNamespaceLister) Get(name string) (*v1.OidcPolicy, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("oidcpolicy"), name)
	}
	return obj.(*v1.OidcPolicy), nil
}

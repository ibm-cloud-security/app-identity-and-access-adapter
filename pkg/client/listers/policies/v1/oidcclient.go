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

// OidcClientLister helps list OidcClients.
type OidcClientLister interface {
	// List lists all OidcClients in the indexer.
	List(selector labels.Selector) (ret []*v1.OidcClient, err error)
	// OidcClients returns an object that can list and get OidcClients.
	OidcClients(namespace string) OidcClientNamespaceLister
	OidcClientListerExpansion
}

// oidcClientLister implements the OidcClientLister interface.
type oidcClientLister struct {
	indexer cache.Indexer
}

// NewOidcClientLister returns a new OidcClientLister.
func NewOidcClientLister(indexer cache.Indexer) OidcClientLister {
	return &oidcClientLister{indexer: indexer}
}

// List lists all OidcClients in the indexer.
func (s *oidcClientLister) List(selector labels.Selector) (ret []*v1.OidcClient, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.OidcClient))
	})
	return ret, err
}

// OidcClients returns an object that can list and get OidcClients.
func (s *oidcClientLister) OidcClients(namespace string) OidcClientNamespaceLister {
	return oidcClientNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// OidcClientNamespaceLister helps list and get OidcClients.
type OidcClientNamespaceLister interface {
	// List lists all OidcClients in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1.OidcClient, err error)
	// Get retrieves the OidcClient from the indexer for a given namespace and name.
	Get(name string) (*v1.OidcClient, error)
	OidcClientNamespaceListerExpansion
}

// oidcClientNamespaceLister implements the OidcClientNamespaceLister
// interface.
type oidcClientNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all OidcClients in the indexer for a given namespace.
func (s oidcClientNamespaceLister) List(selector labels.Selector) (ret []*v1.OidcClient, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.OidcClient))
	})
	return ret, err
}

// Get retrieves the OidcClient from the indexer for a given namespace and name.
func (s oidcClientNamespaceLister) Get(name string) (*v1.OidcClient, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("oidcclient"), name)
	}
	return obj.(*v1.OidcClient), nil
}

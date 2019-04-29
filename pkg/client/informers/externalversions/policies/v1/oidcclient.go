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

// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	time "time"

	policiesv1 "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/apis/policies/v1"
	versioned "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/client/clientset/versioned"
	internalinterfaces "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/client/informers/externalversions/internalinterfaces"
	v1 "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/client/listers/policies/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// OidcClientInformer provides access to a shared informer and lister for
// OidcClients.
type OidcClientInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.OidcClientLister
}

type oidcClientInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewOidcClientInformer constructs a new informer for OidcClient type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewOidcClientInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredOidcClientInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredOidcClientInformer constructs a new informer for OidcClient type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredOidcClientInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AppidV1().OidcClients(namespace).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AppidV1().OidcClients(namespace).Watch(options)
			},
		},
		&policiesv1.OidcClient{},
		resyncPeriod,
		indexers,
	)
}

func (f *oidcClientInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredOidcClientInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *oidcClientInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&policiesv1.OidcClient{}, f.defaultInformer)
}

func (f *oidcClientInformer) Lister() v1.OidcClientLister {
	return v1.NewOidcClientLister(f.Informer().GetIndexer())
}

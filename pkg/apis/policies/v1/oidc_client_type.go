package v1

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OidcClient struct {
	meta_v1.TypeMeta   `json:",inline"`
	meta_v1.ObjectMeta `json:"metadata,omitempty"`

	Spec OidcClientSpec `json:"spec"`
}

// OidcClientSpec is the spec for a OidcClient resource
type OidcClientSpec struct {
	ClientName       string `json:"oidcClientName"`
	ClientId         string `json:"clientId"`
	DiscoveryUrl     string `json:"discoveryUrl"`
	ClientSecret     string `json:"clientSecret"`
	ClientSecretName string `json:"clientSecretRef.name"`
	ClientSecretKey  string `json:"clientSecretRef.key"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OidcClientList is a list of OidcClient resources
type OidcClientList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []OidcClient `json:"items"`
}

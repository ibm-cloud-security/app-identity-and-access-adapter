package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OidcConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OidcConfigSpec `json:"spec"`
}

// OidcConfigSpec is the spec for a OidcConfig resource
type OidcConfigSpec struct {
	ClientName      string
	AuthMethod      string          `json:"authMethod"`
	ClientID        string          `json:"clientId"`
	ClientCallback  string          `json:"callback"`
	DiscoveryURL    string          `json:"discoveryUrl"`
	ClientSecret    string          `json:"clientSecret"`
	ClientSecretRef ClientSecretRef `json:"clientSecretRef"`
}

type ClientSecretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OidcConfigList is a list of OidcConfig resources
type OidcConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []OidcConfig `json:"items"`
}

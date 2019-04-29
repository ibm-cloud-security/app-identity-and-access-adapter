package v1

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OidcPolicy struct {
	meta_v1.TypeMeta   `json:",inline"`
	meta_v1.ObjectMeta `json:"metadata,omitempty"`

	Spec OidcPolicySpec `json:"spec"`
}

// OidcPolicySpec is the spec for a OidcPolicy resource
type OidcPolicySpec struct {
	ClientName string          `json:"oidcClientName"`
	Target     []TargetElement `json:"target"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OidcPolicyList is a list of OidcPolicy resources
type OidcPolicyList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []OidcPolicy `json:"items"`
}

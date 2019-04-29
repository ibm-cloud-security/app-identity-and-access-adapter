package v1

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type JwtPolicy struct {
	meta_v1.TypeMeta   `json:",inline"`
	meta_v1.ObjectMeta `json:"metadata,omitempty"`

	Spec   JwtPolicySpec   `json:"spec"`
	Status JwtPolicyStatus `json:"status"`
}

// JwtPolicySpec is the spec for a JwkPolicy resource
type JwtPolicySpec struct {
	JwksURL string       	`json:"jwksUrl"`
	Target []TargetElement	`json:"target"`
}

type JwtPolicyStatus struct {
	Zaa string `json:"zaa"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// JwkPolicyList is a list of JwkPolicy resources
type JwtPolicyList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []JwtPolicy `json:"items"`
}

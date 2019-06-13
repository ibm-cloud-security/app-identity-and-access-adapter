package v1

import (
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type JwtConfig struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec JwtConfigSpec `json:"spec"`
}

// JwtConfigSpec is the spec for a JwtConfig resource
type JwtConfigSpec struct {
    JwksURL string          `json:"jwksUrl"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// JwtConfigList is a list of JwtConfig resources
type JwtConfigList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata"`

    Items []JwtConfig `json:"items"`
}

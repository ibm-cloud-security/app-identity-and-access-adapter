package crd

type CRD interface {
	GetName() string
	GetNamespace() string
}

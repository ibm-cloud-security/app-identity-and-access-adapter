package policy

// Service identifies a Kubernetes service
type Service struct {
	// Namespace is the group the service lives in
	Namespace string
	// Name is the name of the service
	Name string
}

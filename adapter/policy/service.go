package policy

// Service identifies a Kubernets service
type Service struct {
	// Namespace is the group the service live in
	Namespace string
	// Name is the name of the service
	Name string
}
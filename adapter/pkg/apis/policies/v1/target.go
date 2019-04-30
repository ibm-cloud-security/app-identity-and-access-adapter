package v1

type TargetElement struct {
	ServiceName string   `json:"serviceName"`
	Paths       []string `json:"paths"`
}

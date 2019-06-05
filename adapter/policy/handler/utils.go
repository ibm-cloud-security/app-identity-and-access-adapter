package handler

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

func parseTarget(target []v1.TargetElement, namespace string) []policy.Endpoint {
	endpoints := make([]policy.Endpoint, 0)
	if len(target) > 0 {
		for _, items := range target {
			service := items.ServiceName
			if items.Paths != nil && len(items.Paths) > 0 {
				for _, path := range items.Paths {
					endpoints = append(endpoints, policy.Endpoint{Namespace: namespace, Service: service, Path: path, Method: "*"})
				}
			} else {
				endpoints = append(endpoints, policy.Endpoint{Namespace: namespace, Service: service, Path: "*", Method: "*"})
			}
		}
	}
	return endpoints
}

func generatePolicyMappingKey(crdType policy.Type, namespace string, name string) string {
	return crdType.String() + "/" + namespace + "/" + name
}

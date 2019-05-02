package handler

import (
	"ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"
)

func parseTarget(target []v1.TargetElement, namespace string) []policy.Endpoint {
	endpoints := make([]policy.Endpoint, 0)
	if target != nil && len(target) > 0 {
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

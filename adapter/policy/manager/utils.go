package manager

import (
	"ibmcloudappid/adapter/pkg/apis/policies/v1"
	"istio.io/istio/pkg/log"
)

func parseTarget(target []v1.TargetElement, namespace string) []endpoint {
	log.Infof("%v", target)
	endpoints := make([]endpoint, 0)
	if target != nil || len(target) != 0 {
		for _, items := range target {
			service := items.ServiceName
			if items.Paths != nil || len(items.Paths) != 0 {
				for _, path := range items.Paths {
					endpoints = append(endpoints, endpoint{namespace: namespace, service: service, path: path, method: "*"})
				}
			} else {
				endpoints = append(endpoints, endpoint{namespace: namespace, service: service, path: "*", method: "*"})
			}
		}
	}
	return endpoints
}

func endpointsToCheck(namespace string, svc string, path string, method string) []endpoint {
	return []endpoint{
		endpoint{namespace: namespace, service: svc, path: path, method: method},
		endpoint{namespace: namespace, service: svc, path: path, method: "*"},
		endpoint{namespace: namespace, service: svc, path: "*", method: "*"},
	}
}

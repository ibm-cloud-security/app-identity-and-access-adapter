package handler

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

func parseTarget(target []v1.TargetElement, namespace string) []policy.Endpoint {
	endpoints := make([]policy.Endpoint, 0)
	if len(target) > 0 {
		for _, items := range target {
			service := items.ServiceName
			if items.Paths != nil && len(items.Paths) > 0 {
				for _, path := range items.Paths {
					if path != "/" {
						path = strings.TrimRight(path, "/")
					}
					endpoints = append(endpoints, policy.Endpoint{Namespace: namespace, Service: service, Path: path, Method: "*"})
				}
			} else {
				endpoints = append(endpoints, policy.Endpoint{Namespace: namespace, Service: service, Path: "*", Method: "*"})
			}
		}
	}
	return endpoints
}

func GetKubeSecret(kubeClient kubernetes.Interface, namespace string, ref v1.ClientSecretRef) (*k8sv1.Secret, error) {
	secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ref.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func generatePolicyMappingKey(crdType policy.Type, namespace string, name string) string {
	return crdType.String() + "/" + namespace + "/" + name
}

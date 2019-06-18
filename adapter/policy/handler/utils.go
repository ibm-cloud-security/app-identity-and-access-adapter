package handler

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"

	"strings"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func getEndpoint(service policy.Service, method policy.Method, path string) policy.Endpoint {
	return  policy.Endpoint{
		Service: service,
		Method: method,
		Path: path,
	}
}

func getParsedPolicy(service policy.Service, method policy.Method, path string, policies []v1.PathPolicy) policy.PolicyMapping{
	return policy.NewPolicyMapping(getEndpoint(service, method, path), policies)
}

func parseTarget(target []v1.TargetElement, namespace string) []policy.PolicyMapping {
	targets := make([]policy.PolicyMapping, 0)
	if len(target) > 0 {
		for _, items := range target {
			service := policy.Service{
				Name: items.ServiceName,
				Namespace: namespace,
			}
			if items.Paths != nil && len(items.Paths) > 0 {
				for _, path := range items.Paths {
					method := policy.NewMethod(path.Method)
					if path.Exact != "" {
						if path.Exact != "/" {
							path.Exact = strings.TrimRight(path.Exact, "/")
						}
						targets = append(targets, getParsedPolicy(service, method, path.Exact, path.Policies))
					}

					if path.Prefix != "" {
						if !strings.HasSuffix(path.Prefix,"/*") {
							if strings.HasSuffix(path.Prefix,"/") {
								path.Prefix = path.Prefix + "*"
							} else {
								path.Prefix = path.Prefix + "/*"
							}
						}
						targets = append(targets, getParsedPolicy(service, method, path.Prefix, path.Policies))
					}

					if path.Exact == "" && path.Prefix == "" {
						targets = append(targets, getParsedPolicy(service, method, "/*", path.Policies))
					}
				}
			}
		}
	}
	return targets
}

func GetKubeSecret(kubeClient kubernetes.Interface, namespace string, ref v1.ClientSecretRef) (*k8sv1.Secret, error) {
	return kubeClient.CoreV1().Secrets(namespace).Get(ref.Name, metav1.GetOptions{})
}

/*
func generatePolicyMappingKey(crdType policy.Type, namespace string, name string) string {
	return crdType.String() + "/" + namespace + "/" + name
}

*/

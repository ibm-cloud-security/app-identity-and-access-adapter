package crdeventhandler

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	v1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
)

func getPathConfig(exact string, prefix string, method string, policies []v1.PathPolicy) v1.PathConfig {
	return v1.PathConfig{
		Exact:    exact,
		Prefix:   prefix,
		Method:   method,
		Policies: policies,
	}
}

func getPathConfigs(path v1.PathConfig) []v1.PathConfig {
	return []v1.PathConfig{path,}
}

func getTargetElements(service string, paths []v1.PathConfig) v1.TargetElement {
	return v1.TargetElement{
		ServiceName: service,
		Paths:       paths,
		ServiceHost: service,
	}
}

type output struct {
	policies        []policy.PolicyMapping
	total           int
	serviceMappings map[policy.Service]string
}

func TestParsedTarget(t *testing.T) {
	tests := [] struct {
		name    string
		targets []v1.TargetElement
		output  output
	}{
		{
			name: "No exact/prefix provided",
			targets: []v1.TargetElement{
				getTargetElements(service, getPathConfigs(getPathConfig("", "", "", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("", "", "GET", getDefaultPathPolicy()))),
			},
			output: output{
				total: 2,
				policies: []policy.PolicyMapping{
					{
						Endpoint: getEndpoint(getDefaultService(), policy.ALL, "/*"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/*"),
						Actions:  getDefaultPathPolicy(),
					},
				},
				serviceMappings: map[policy.Service]string{policy.Service{Name: service, Namespace: "ns"}: service},
			},
		},
		{
			name: "exact path test",
			targets: []v1.TargetElement{
				getTargetElements(service, getPathConfigs(getPathConfig("/", "", "", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("/path", "", "GET", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("/path1/", "", "GET", getDefaultPathPolicy()))),
			},
			output: output{
				total: 3,
				policies: []policy.PolicyMapping{
					{
						Endpoint: getEndpoint(getDefaultService(), policy.ALL, "/"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path1"),
						Actions:  getDefaultPathPolicy(),
					},
				},
				serviceMappings: map[policy.Service]string{policy.Service{Name: service, Namespace: "ns"}: service},
			},
		},
		{
			name: "prefix path test",
			targets: []v1.TargetElement{
				getTargetElements(service, getPathConfigs(getPathConfig("", "/", "", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("", "/path", "GET", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("", "/path1/", "GET", getDefaultPathPolicy()))),
			},
			output: output{
				total: 3,
				policies: []policy.PolicyMapping{
					{
						Endpoint: getEndpoint(getDefaultService(), policy.ALL, "/*"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path/*"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path1/*"),
						Actions:  getDefaultPathPolicy(),
					},
				},
				serviceMappings: map[policy.Service]string{policy.Service{Name: service, Namespace: "ns"}: service},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(st *testing.T) {
			st.Parallel()
			result := ParseTarget(test.targets, ns)
			assert.Equal(t, len(result), test.output.total)
			if !reflect.DeepEqual(result, test.output.policies) {
				assert.Fail(t, fmt.Sprintf("expected out to have value %v, got %v", test.output.policies, result))
			}
			serviceMappings := ParseServiceHosts(test.targets, ns)
			if !reflect.DeepEqual(serviceMappings, test.output.serviceMappings) {
				assert.Fail(t, fmt.Sprintf("expected out to have value %v, got %v", test.output.serviceMappings, serviceMappings))
			}
		})
	}
}

package crdeventhandler

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

func getPathConfig(exact string, prefix string, method string, policies []v1.PathPolicy) v1.PathConfig {
	return v1.PathConfig{
		Exact: exact,
		Prefix: prefix,
		Method: method,
		Policies: policies,
	}
}

func getPathConfigs(path v1.PathConfig) []v1.PathConfig{
	return []v1.PathConfig{ path,}
}

func getTargetElements(service string, paths []v1.PathConfig) v1.TargetElement {
	return v1.TargetElement{
		ServiceName: service,
		Paths: paths,
	}
}


type output struct {
	policies []policy.PolicyMapping
	total int
}

func TestParsedTarget(t *testing.T) {
	tests := [] struct{
		name string
		targets  []v1.TargetElement
		output output
	} {
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
		})
	}
}

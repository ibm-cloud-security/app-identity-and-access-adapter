package v1

type TargetElement struct {
	ServiceName string       `json:"serviceName"`
	Paths       []PathConfig `json:"paths"`
}

type PathConfig struct {
	Exact    string       `json:"exact"`
	Prefix   string       `json:"prefix"`
	Method   string       `json:"method"`
	Policies []PathPolicy `json:"policies"`
}

type PathPolicy struct {
	PolicyType  string `json:"policyType"`
	Config      string `json:"config"`
	RedirectUri string `json:"redirectUri"`
	Rules       []Rule `json:"rules"`
}

type Rule struct {
	Claim string   `json:"claim"`
	Value []string `json:"value"`
	Match string   `json:"match"`
}

package crd

type OIDCPolicy struct {
	Name         string
	NameSpace    string
	ClientName   string
	ClientID     string
	DiscoveryURL string
	ClientSecret string
}

func (p *OIDCPolicy) GetName() string {
	return p.Name
}

func (p *OIDCPolicy) GetNamespace() string {
	return p.NameSpace
}

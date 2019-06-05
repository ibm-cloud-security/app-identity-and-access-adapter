package crd

type JWTService struct {
	Name  string
	Paths []string
}
type JWTPolicy struct {
	Name      string
	NameSpace string
	JwksURL   string
	Service   []JWTService
}

func (p *JWTPolicy) GetName() string {
	return p.Name
}

func (p *JWTPolicy) GetNamespace() string {
	return p.NameSpace
}

package v1

type CrdType int

const (
	JWTCONFIG CrdType = iota
	OIDCCONFIG
	POLICY
	NONE
)

func (c CrdType) String() string {
	return [...]string{"JwtConfig", "OidcConfig", "Policy"}[c]
}

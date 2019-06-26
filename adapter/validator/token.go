package validator

type Token int

const (
	Access Token = iota
	ID
)

func (t Token) String() string {
	return [...]string{"access_token", "id_token"}[t]
}
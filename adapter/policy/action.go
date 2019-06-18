package policy

type Method int

const (
	ALL Method = iota
	GET
	PUT
	POST
	DELETE
	PATCH
)

func (m Method) String() string {
	return [...]string{"ALL", "GET", "PUT", "POST", "DELETE", "PATCH"}[m]
}

func NewMethod(method string) Method {
	switch method {
	case "ALL":
		return ALL
	case "GET":
		return GET
	case "PUT":
		return PUT
	case "POST":
		return POST
	case "DELETE":
		return DELETE
	case "PATCH":
		return PATCH
	default:
		return ALL
	}
}

type Actions = map[Method]RoutePolicy

// New creates a new Actions
func NewActions() Actions {
	return make(map[Method]RoutePolicy)
}

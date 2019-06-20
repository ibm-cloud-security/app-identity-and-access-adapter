package policy

// Method is an enum of HTTP Methods
type Method int

// Supported HTTP methods
const (
	ALL Method = iota
	GET
	PUT
	POST
	DELETE
	PATCH
)

// String converts a Method type to its prettified string
func (m Method) String() string {
	return [...]string{"ALL", "GET", "PUT", "POST", "DELETE", "PATCH"}[m]
}

// NewMethod creates a Method type from a string
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

// Actions maps Methods to RoutePolicies
type Actions = map[Method]RoutePolicy

// NewActions creates a new Actions map
func NewActions() Actions {
	return make(map[Method]RoutePolicy)
}

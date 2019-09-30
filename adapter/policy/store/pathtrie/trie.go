package pathtrie

// Exposes the Trie structure capabilities.
type Trie interface {
	Get(key string) interface{}
	GetActions(key string, parentValue bool) interface{}
	Put(key string, value interface{}) bool
	Delete(key string) bool
}

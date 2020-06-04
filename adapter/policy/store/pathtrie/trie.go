package pathtrie

// Exposes the Trie structure capabilities.
type Trie interface {
	Get(key string) interface{}
	GetActions(key string) interface{}
	GetPrefixActions(key string) interface{}
	Put(key string, value interface{}) bool
	Delete(key string) bool
}

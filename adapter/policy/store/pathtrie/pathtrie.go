package pathtrie

type PathTrie struct {
	segmenter StringSegmenter
	value     interface{}
	children  map[string]*PathTrie
}

func PathTrieNode() *PathTrie {
	return &PathTrie{
		segmenter: PathSegmenter,
		children:  make(map[string]*PathTrie),
	}
}

// NewPathTrie allocates and returns a new *PathTrie.
func NewPathTrie() *PathTrie {
	trie := PathTrieNode()
	trie.Put("/", nil)
	return trie
}

// Get returns the value stored at the given key. Returns nil for internal
// nodes or for nodes with a value of nil.
func (trie *PathTrie) Get(key string) interface{} {
	node := trie
	for part, i := trie.segmenter(key, 0); ; part, i = trie.segmenter(key, i) {
		node = node.children[part]
		if node == nil {
			return nil
		}
		if i == -1 {
			break
		}
	}
	return node.value
}

// Get returns the actions stored for the given endpoint.
func (trie *PathTrie) GetActions(key string) interface{} {
	prefix := "/*"
	node := trie
	parent := trie.children[prefix]
	for part, i := trie.segmenter(key, 0); ; part, i = trie.segmenter(key, i) {
		node = node.children[part]
		if node != nil && node.children[prefix] != nil {
			parent = node.children[prefix]
		}
		if node == nil || i == -1 {
			break
		}
	}

	if node == nil || node.value == nil {
		if parent == nil {
			return nil
		} else {
			return parent.value
		}
	}
	return node.value
}

// Put inserts the value into the trie at the given key, replacing any
// existing items. It returns true if the put adds a new value, false
// if it replaces an existing value.
// Note that internal nodes have nil values so a stored nil value will not
// be distinguishable and will not be included in Walks.
func (trie *PathTrie) Put(key string, value interface{}) bool {
	node := trie
	for part, i := trie.segmenter(key, 0); ; part, i = trie.segmenter(key, i) {
		child, _ := node.children[part]
		if child == nil {
			child = PathTrieNode()
			node.children[part] = child
		}
		node = child
		if i == -1 {
			break
		}
	}
	// does node have an existing value?
	isNewVal := node.value == nil
	node.value = value
	return isNewVal
}

// Delete removes the value associated with the given key. Returns true if a
// node was found for the given key. If the node or any of its ancestors
// becomes childless as a result, it is removed from the trie.
func (trie *PathTrie) Delete(key string) bool {
	var path []nodeStr // record ancestors to check later
	node := trie
	for part, i := trie.segmenter(key, 0); ; part, i = trie.segmenter(key, i) {
		path = append(path, nodeStr{part: part, node: node})
		node = node.children[part]
		if node == nil {
			// node does not exist
			return false
		}
		if i == -1 {
			break
		}
	}
	// delete the node value
	node.value = nil
	// if leaf, remove it from its parent's children map. Repeat for ancestor path.
	if node.isLeaf() {
		// iterate backwards over path
		for i := len(path) - 1; i >= 0; i-- {
			parent := path[i].node
			part := path[i].part
			delete(parent.children, part)
			if parent.value != nil || !parent.isLeaf() {
				// parent has a value or has other children, stop
				break
			}
		}
	}
	return true // node (internal or not) existed and its value was nil'd
}

// PathTrie node and the part string key of the child the path descends into.
type nodeStr struct {
	node *PathTrie
	part string
}

func (trie *PathTrie) isLeaf() bool {
	return len(trie.children) == 0
}
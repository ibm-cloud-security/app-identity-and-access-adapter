package pathtrie

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Case struct {
	key string
	value interface{}
}

func getCases() []Case {
	return []Case{
		{"/path", 2},
		{"/path/*", 3},
		{"/path/path1", 4},
		{"/home", 5},
		{"/web", 6},
		{"/web/*", 7},
	}
}

func TestPathTrie(t *testing.T) {
	trie := NewPathTrie()
	value := 100
	cases := getCases()
	cases = append(cases, Case{"/", 0}, Case{"/*", 1})
	// get missing keys
	for _, c := range cases {
		if value := trie.Get(c.key); value != nil {
			t.Errorf("expected key %s to be missing, found value %v", c.key, value)
		}
	}

	// initial put
	for _, c := range cases {
		if isNew := trie.Put(c.key, value); !isNew {
			t.Errorf("expected key %s to be missing", c.key)
		}
	}

	// subsequent put
	for _, c := range cases {
		if isNew := trie.Put(c.key, c.value); isNew {
			t.Errorf("expected key %s to have a value already", c.key)
		}
	}

	// get
	for _, c := range cases {
		if value := trie.Get(c.key); value != c.value {
			t.Errorf("expected key %s to have value %v, got %v", c.key, c.value, value)
		}
	}

	// delete, expect Delete to return true indicating a node was nil'd
	for _, c := range cases {
		if deleted := trie.Delete(c.key); !deleted {
			t.Errorf("expected key %s to be deleted", c.key)
		}
	}

	// delete cleaned all the way to the first character
	// expect Delete to return false bc no node existed to nil
	for _, c := range cases {
		if deleted := trie.Delete(string(c.key[0])); deleted {
			t.Errorf("expected key %s to be cleaned by delete", string(c.key[0]))
		}
	}

	// get deleted keys
	for _, c := range cases {
		if value := trie.Get(c.key); value != nil {
			t.Errorf("expected key %s to be deleted, got value %v", c.key, value)
		}
	}

}

func TestPathTrie_GetActions(t *testing.T) {
	trie := NewPathTrie()
	initialValues := getCases()

	// initial put
	for _, c := range initialValues {
		if isNew := trie.Put(c.key, c.value); !isNew {
			assert.Fail(t, fmt.Sprintf("expected key %s to be missing", c.key))
		}
	}

	cases := getCases()
	cases = append(cases, Case{"/home/user", nil}, Case{"/path/home", 3}, Case{"/web/home", 7})
	// Get Actions : return parent actions
	for _, c := range cases {
		if value := trie.GetActions(c.key, true); value != c.value {
			assert.Fail(t, fmt.Sprintf("expected key %s to have value %v, got %v", c.key, c.value, value))
		}
	}

	cases = []Case{
		{"/web/user", nil},
		{"/path", 2},
		{"/path/path1", 4},
		{"/path/path2", nil},
	}

	// Get Actions
	for _, c := range cases {
		if value := trie.GetActions(c.key, false); value != c.value {
			assert.Fail(t, fmt.Sprintf("expected key %s to have value %v, got %v", c.key, c.value, value))
		}
	}
}
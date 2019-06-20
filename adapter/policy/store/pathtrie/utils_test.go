package pathtrie

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathSegmenter(t *testing.T) {
	type result struct {
		segment string
		next    int
	}
	type testObj struct {
		path     string
		expected result
	}

	tests := []testObj{
		{
			path: "",
			expected: result{
				segment: "",
				next:    -1,
			},
		},
		{
			path: "/",
			expected: result{
				segment: "/",
				next:    -1,
			},
		},
		{
			path: "/*",
			expected: result{
				segment: "/*",
				next:    -1,
			},
		},
		{
			path: "/path",
			expected: result{
				segment: "/path",
				next:    -1,
			},
		},
		{
			path: "/path/user",
			expected: result{
				segment: "/path",
				next:    5,
			},
		},
	}

	testRunner := func(test testObj) {
		t.Run("PathSegmenter", func(t *testing.T) {
			t.Parallel()
			segment, next := PathSegmenter(test.path, 0)
			assert.Equal(t, test.expected.segment, segment)
			assert.Equal(t, test.expected.next, next)
		})
	}

	for _, test := range tests {
		testRunner(test)
	}
}

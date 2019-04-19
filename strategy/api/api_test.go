package apistrategy

import (
	"testing"
)

func TestSum(t *testing.T) {
	total := 10
	if total != 10 {
		t.Errorf("Sum was incorrect, got: %d, want: %d.", total, 10)
	}
}

func TestSum2(t *testing.T) {
	total := 10
	if total != 10 {
		t.Errorf("Sum was incorrect, got: %d, want: %d.", total, 10)
	}
}

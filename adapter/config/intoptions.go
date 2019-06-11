package config

import (
	"errors"
	"strconv"
	"strings"
)

// IntOptions holds Integer configuration options as part of combra command line parameters
type IntOptions struct {
	// Options contains Enum of supported Integers
	Options map[int]struct{}
	// Value is the selected value from the enum map
	Value int
}

// String converts the core value to a string
func (o *IntOptions) String() string {
	return strconv.Itoa(int(o.Value))
}

// Set takes the user input validates it and stores it
func (o *IntOptions) Set(inp string) error {
	i, err := strconv.ParseInt(inp, 10, 8)
	if err != nil {
		return err
	}

	v := int(i)
	if _, ok := o.Options[v]; !ok {
		return errors.New("Expected value in " + mapKeysToString(o.Options))
	}

	o.Value = v
	return nil
}

// Type returns the expected command line type the user must input as a string
func (o *IntOptions) Type() string {
	return "int"
}

// mapKeysToString converts a map to a string array
func mapKeysToString(m map[int]struct{}) string {
	options := "["
	for v := range m {
		options += strconv.Itoa(int(v)) + ","
	}
	return strings.Trim(options, ",") + "]"
}

package cmdarg

import (
	"strings"
)

// Arg is used by flag to accept multiple arguments.
type Arg []string

// String returns the string representation of the Arg slice.
func (c *Arg) String() string {
	if c == nil {
		return ""
	}
	return strings.Join([]string(*c), " ")
}

// Set is the method flag package calls to set a value to the Arg slice.
func (c *Arg) Set(value string) error {
	if c == nil {
		*c = make([]string, 0)
	}
	*c = append(*c, value)
	return nil
}

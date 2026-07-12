package api

import (
	"fmt"
	"strconv"
)

// singleIndexFlag records whether an index was explicitly provided and rejects
// negative or repeated values. Keeping presence separate from value prevents a
// user-supplied sentinel such as -1 from being treated as "not specified".
type singleIndexFlag struct {
	value int
	set   bool
}

func (f *singleIndexFlag) String() string {
	return strconv.Itoa(f.value)
}

func (f *singleIndexFlag) Set(value string) error {
	if f.set {
		return fmt.Errorf("-i/-index may only be specified once")
	}
	index, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid index %q: %w", value, err)
	}
	if index < 0 {
		return fmt.Errorf("index must be zero or greater")
	}
	f.value = index
	f.set = true
	return nil
}

package reality

import (
	_ "unsafe"

	_ "github.com/xtls/reality"
)

//go:linkname aesgcmPreferred github.com/xtls/reality.aesgcmPreferred
func aesgcmPreferred(ciphers []uint16) bool

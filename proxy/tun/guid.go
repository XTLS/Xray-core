package tun

import (
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/errors"
)

// ParseGUID parses a canonical textual GUID, as in
// "00000000-0000-0000-0000-000000000000", into the 16 bytes it denotes.
// The form is all that is accepted, not the other ones uuid.Parse takes,
// such as one without hyphens.
func ParseGUID(s string) ([16]byte, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return [16]byte{}, errors.New("invalid guid: ", s).Base(err)
	}
	if id.String() != strings.ToLower(s) {
		return [16]byte{}, errors.New("invalid guid: ", s, ", want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}
	return id, nil
}

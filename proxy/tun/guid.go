package tun

import (
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/errors"
)

// ParseGUID parses a canonical textual GUID, as in
// "00000000-0000-0000-0000-000000000000", into the 16 bytes it denotes.
// The form is all that is accepted, not the other ones uuid.Parse takes,
// such as one without hyphens; the length check is what rules those out.
func ParseGUID(s string) ([16]byte, error) {
	if len(s) != 36 {
		return [16]byte{}, errors.New("invalid guid: ", s, ", want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return [16]byte{}, errors.New("invalid guid: ", s, ", want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").Base(err)
	}
	return id, nil
}

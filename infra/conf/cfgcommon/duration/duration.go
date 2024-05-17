package duration

import (
	"encoding/json"
	"fmt"
	"time"
)

type Duration int64

func (d *Duration) MarshalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("nil pointer dereference")
	}
	dr := time.Duration(*d)
	return json.Marshal(dr.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	if d == nil {
		return fmt.Errorf("nil pointer dereference")
	}
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		dr, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(dr)
		return nil
	default:
		return fmt.Errorf("invalid duration: %v", v)
	}
}

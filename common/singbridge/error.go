package singbridge

import E "github.com/sagernet/sing/common/exceptions"

func ReturnError(err error) error {
	if E.IsClosed(err) {
		return nil
	}
	return err
}

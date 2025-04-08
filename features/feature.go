package features

import (
	"github.com/hosemorinho412/xray-core/common"
)

// Feature is the interface for Xray features. All features must implement this interface.
// All existing features have an implementation in app directory. These features can be replaced by third-party ones.
type Feature interface {
	common.HasType
	common.Runnable
}

// +build !confonly

package reverse

import (
	"crypto/rand"
	"io"

	"github.com/xtls/xray-core/v1/common/dice"
)

func (c *Control) FillInRandom() {
	randomLength := dice.Roll(64)
	c.Random = make([]byte, randomLength)
	io.ReadFull(rand.Reader, c.Random)
}

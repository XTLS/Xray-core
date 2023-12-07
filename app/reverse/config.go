package reverse

import (
	"crypto/rand"
	"io"

	"github.com/4nd3r5on/Xray-core/common/dice"
)

func (c *Control) FillInRandom() {
	randomLength := dice.Roll(64)
	c.Random = make([]byte, randomLength)
	io.ReadFull(rand.Reader, c.Random)
}

package reverse

import (
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
)

func (c *Control) FillInRandom() {
	randomLength := mrand.N(64)
	randomLength++
	c.Random = make([]byte, randomLength)
	io.ReadFull(rand.Reader, c.Random)
}

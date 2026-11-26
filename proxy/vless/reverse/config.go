package reverse

import (
	"crypto/rand"
	"io"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/net"
)

func (c *Control) FillInRandom() {
	randomLength := dice.Roll(64)
	randomLength++
	c.Random = make([]byte, randomLength)
	io.ReadFull(rand.Reader, c.Random)
}

const internalDomain = "reverse"

func isInternalDomain(dest net.Destination) bool {
	return dest.Address.Family().IsDomain() && dest.Address.Domain() == internalDomain
}

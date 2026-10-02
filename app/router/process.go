package router

import (
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

type processLookupFunc func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)

// processRoutingContext owns a lazy process lookup for one routing decision.
// Re-querying ownership between rules can let a disappearing Android socket
// bypass both an unidentified-app block and its app-specific route.
type processRoutingContext struct {
	routing.Context
	findProcess          processLookupFunc
	mu                   sync.Mutex
	lookedUp             bool
	retryWithDestination bool
	pid                  int
	name, path           string
	err                  error
}

func (c *processRoutingContext) lookup(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	completeDestination := destIP != "" && destPort != 0
	// A domain-only context may gain its destination on the DNS retry. Only
	// retry a failed lookup that was made without that destination.
	if !c.lookedUp || (c.retryWithDestination && completeDestination) {
		findProcess := c.findProcess
		if findProcess == nil {
			findProcess = net.FindProcess
		}
		c.pid, c.name, c.path, c.err = findProcess(network, srcIP, srcPort, destIP, destPort)
		c.lookedUp = true
		c.retryWithDestination = c.err != nil && !completeDestination
	}
	return c.pid, c.name, c.path, c.err
}

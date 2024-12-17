// Package session provides functions for sessions of incoming requests.
package session // import "github.com/xtls/xray-core/common/session"

import (
	"context"
	"math/rand"
	"sync"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
)

// NewID generates a new ID. The generated ID is high likely to be unique, but not cryptographically secure.
// The generated ID will never be 0.
func NewID() c.ID {
	for {
		id := c.ID(rand.Uint32())
		if id != 0 {
			return id
		}
	}
}

// ExportIDToError transfers session.ID into an error object, for logging purpose.
// This can be used with error.WriteToLog().
func ExportIDToError(ctx context.Context) errors.ExportOption {
	id := c.IDFromContext(ctx)
	return func(h *errors.ExportOptionHolder) {
		h.SessionID = uint32(id)
	}
}

// Inbound is the metadata of an inbound connection.
type Inbound struct {
	// Source address of the inbound connection.
	Source net.Destination
	// Gateway address.
	Gateway net.Destination
	// Tag of the inbound proxy that handles the connection.
	Tag string
	// Name of the inbound proxy that handles the connection.
	Name string
	// User is the user that authenticates for the inbound. May be nil if the protocol allows anonymous traffic.
	User *protocol.MemoryUser
	// Conn is actually internet.Connection. May be nil.
	Conn net.Conn
	// Timer of the inbound buf copier. May be nil.
	Timer *signal.ActivityTimer
	// CanSpliceCopy is a property for this connection
	// 1 = can, 2 = after processing protocol info should be able to, 3 = cannot
	CanSpliceCopy int
}

// Outbound is the metadata of an outbound connection.
type Outbound struct {
	// Target address of the outbound connection.
	OriginalTarget net.Destination
	Target         net.Destination
	RouteTarget    net.Destination
	// Gateway address
	Gateway net.Address
	// Tag of the outbound proxy that handles the connection.
	Tag string
	// Name of the outbound proxy that handles the connection.
	Name string
	// Conn is actually internet.Connection. May be nil. It is currently nil for outbound with proxySettings
	Conn net.Conn
	// CanSpliceCopy is a property for this connection
	// 1 = can, 2 = after processing protocol info should be able to, 3 = cannot
	CanSpliceCopy int
}

// SniffingRequest controls the behavior of content sniffing.
type SniffingRequest struct {
	ExcludeForDomain               []string
	OverrideDestinationForProtocol []string
	Enabled                        bool
	MetadataOnly                   bool
	RouteOnly                      bool
}

// Content is the metadata of the connection content.
type Content struct {
	// Protocol of current content.
	Protocol string

	SniffingRequest SniffingRequest

	Attributes map[string]string

	SkipDNSResolve bool

	mu sync.Mutex

	isLocked bool
}

// Sockopt is the settings for socket connection.
type Sockopt struct {
	// Mark of the socket connection.
	Mark int32
}

// Some how when using mux, there will be a same ctx between different requests
// This will cause problem as it's designed for single request, like concurrent map writes
// Add a Mutex as a temp solution

// SetAttribute attaches additional string attributes to content.
func (c *Content) SetAttribute(name string, value string) {
	if c.isLocked {
		errors.LogError(context.Background(), "Multiple goroutines are tring to access one routing content, tring to write ", name, ":", value)
	}
	c.mu.Lock()
	c.isLocked = true
	defer func() {
		c.isLocked = false
		c.mu.Unlock()
	}()

	if c.Attributes == nil {
		c.Attributes = make(map[string]string)
	}
	c.Attributes[name] = value
}

// Attribute retrieves additional string attributes from content.
func (c *Content) Attribute(name string) string {
	c.mu.Lock()
	c.isLocked = true
	defer func() {
		c.isLocked = false
		c.mu.Unlock()
	}()
	if c.Attributes == nil {
		return ""
	}
	return c.Attributes[name]
}

func (c *Content) AttributeLen() int {
	c.mu.Lock()
	c.isLocked = true
	defer func() {
		c.isLocked = false
		c.mu.Unlock()
	}()
	return len(c.Attributes)
}

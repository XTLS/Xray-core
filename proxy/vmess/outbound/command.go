package outbound

import (

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

// protocol.CommandSwitchAccount was functioned as dynamic port/user command by VMess.
// Dynamic port/user relying on PickServer() which was removed as the design does not
// fit in time as time changes.

// As a stub command consumer.
func (h *Handler) handleCommand(dest net.Destination, cmd protocol.ResponseCommand) {
	// switch typedCommand := cmd.(type) {
	// case *protocol.CommandSwitchAccount:
	//	 if typedCommand.Host == nil {
	//		 typedCommand.Host = dest.Address
	//	 }
	//	 h.handleSwitchAccount(typedCommand)
	switch cmd.(type) {
	default:
	}
}

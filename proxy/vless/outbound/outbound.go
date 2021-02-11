package outbound

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/connman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	simplesocks "github.com/xtls/xray-core/proxy/simplesocks/outbound"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	xtls_show = false
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))

	const defaultFlagValue = "NOT_DEFINED_AT_ALL"

	xtlsShow := platform.NewEnvFlag("xray.vless.xtls.show").GetValue(func() string { return defaultFlagValue })
	if xtlsShow == "true" {
		xtls_show = true
	}
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	serverList    *protocol.ServerList
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
	smux          bool
	connManager   *connman.SmuxManager
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Vnext {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, newError("failed to parse server spec").Base(err).AtError()
		}
		serverList.AddServer(s)
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		serverList:    serverList,
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		connManager:   connman.NewSmuxManager(),
	}

	return handler, nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var rec *protocol.ServerSpec
	var conn internet.Connection
	var useSmux bool
	var request *protocol.RequestHeader

	// Get outbound metadata from context
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified").AtError()
	}

	// Dial to remote server
	if err := retry.ExponentialBackoff(5, 200).On(func() error {
		rec = h.serverPicker.PickServer()
		useSmux = rec.UseSmux()

		// Create request header
		request = &protocol.RequestHeader{
			Version: encoding.Version,
			User:    rec.PickUser(),
			Command: h.getCommand(outbound.Target, useSmux),
			Address: outbound.Target.Address,
			Port:    outbound.Target.Port,
		}

		// Use connection manager to obtain the connection to remote server if Smux is used, otherwise dial directly
		if useSmux {
			smuxConn, err := h.connManager.GetConnection(ctx, rec.Destination(), dialer, request, h.setupSmuxConnection)
			if err != nil {
				return err
			}
			conn = smuxConn
		} else {
			baseConn, err := dialer.Dial(ctx, rec.Destination())
			if err != nil {
				return err
			}
			conn, err = NewOutboundConn(baseConn, request, &encoding.Addons{
				Flow: request.User.Account.(*vless.MemoryAccount).Flow,
			})
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return newError("failed to find an available destination").Base(err).AtWarning()
	}

	defer conn.Close()

	newError("tunneling request to ", outbound.Target, " via ", rec.Destination()).AtInfo().WriteToLog(session.ExportIDToError(ctx))

	// Check if Smux should be used
	if useSmux {
		if err := simplesocks.HandleOutboundConnection(ctx, conn, link, request); err != nil {
			return newError("simplesocks connection ends").Base(err).AtInfo()
		}
		return nil
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if err := buf.Copy(clientReader, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transfer request payload").Base(err).AtInfo()
		}

		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		if err := buf.Copy(buf.NewReader(conn), clientWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return newError("connection ends").Base(err).AtInfo()
	}

	return nil
}

// Determine which command the request encapsulates based on the destination and Smux option
func (h *Handler) getCommand(destination net.Destination, useSmux bool) protocol.RequestCommand {
	command := protocol.RequestCommandTCP
	if destination.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if destination.Address.Family().IsDomain() && destination.Address.Domain() == "v1.mux.cool" {
		command = protocol.RequestCommandMux
	}
	if useSmux {
		command = protocol.RequestCommandSmux
	}
	return command
}

// Helper function to setup Smux connection
func (h *Handler) setupSmuxConnection(conn internet.Connection, header *protocol.RequestHeader) (internet.Connection, error) {
	conn, err := NewOutboundConn(conn, header,
		&encoding.Addons{
			Flow: header.User.Account.(*vless.MemoryAccount).Flow,
		})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

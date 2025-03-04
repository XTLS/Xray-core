package session

import (
	"context"
	_ "unsafe"

	"github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

//go:linkname IndependentCancelCtx context.newCancelCtx
func IndependentCancelCtx(parent context.Context) context.Context

const (
	inboundSessionKey         ctx.SessionKey = 1
	outboundSessionKey        ctx.SessionKey = 2
	contentSessionKey         ctx.SessionKey = 3
	muxPreferredSessionKey    ctx.SessionKey = 4
	sockoptSessionKey         ctx.SessionKey = 5
	trackedConnectionErrorKey ctx.SessionKey = 6
	dispatcherKey             ctx.SessionKey = 7
	timeoutOnlyKey            ctx.SessionKey = 8
	allowedNetworkKey         ctx.SessionKey = 9
	handlerSessionKey         ctx.SessionKey = 10
	mitmAlpn11Key             ctx.SessionKey = 11
	mitmServerNameKey         ctx.SessionKey = 12
)

func ContextWithInbound(ctx context.Context, inbound *Inbound) context.Context {
	return context.WithValue(ctx, inboundSessionKey, inbound)
}

func InboundFromContext(ctx context.Context) *Inbound {
	if inbound, ok := ctx.Value(inboundSessionKey).(*Inbound); ok {
		return inbound
	}
	return nil
}

func ContextWithOutbounds(ctx context.Context, outbounds []*Outbound) context.Context {
	return context.WithValue(ctx, outboundSessionKey, outbounds)
}

func ContextCloneOutboundsAndContent(ctx context.Context) context.Context {
	outbounds := OutboundsFromContext(ctx)
	newOutbounds := make([]*Outbound, len(outbounds))
	for i, ob := range outbounds {
		if ob == nil {
			continue
		}

		// copy outbound by value
		v := *ob
		newOutbounds[i] = &v
	}

	content := ContentFromContext(ctx)
	newContent := Content{}
	if content != nil {
		newContent = *content
		if content.Attributes != nil {
			panic("content.Attributes != nil")
		}
	}
	return ContextWithContent(ContextWithOutbounds(ctx, newOutbounds), &newContent)
}

func OutboundsFromContext(ctx context.Context) []*Outbound {
	if outbounds, ok := ctx.Value(outboundSessionKey).([]*Outbound); ok {
		return outbounds
	}
	return nil
}

func ContextWithContent(ctx context.Context, content *Content) context.Context {
	return context.WithValue(ctx, contentSessionKey, content)
}

func ContentFromContext(ctx context.Context) *Content {
	if content, ok := ctx.Value(contentSessionKey).(*Content); ok {
		return content
	}
	return nil
}

// ContextWithMuxPreferred returns a new context with the given bool
func ContextWithMuxPreferred(ctx context.Context, forced bool) context.Context {
	return context.WithValue(ctx, muxPreferredSessionKey, forced)
}

// MuxPreferredFromContext returns value in this context, or false if not contained.
func MuxPreferredFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(muxPreferredSessionKey).(bool); ok {
		return val
	}
	return false
}

// ContextWithSockopt returns a new context with Socket configs included
func ContextWithSockopt(ctx context.Context, s *Sockopt) context.Context {
	return context.WithValue(ctx, sockoptSessionKey, s)
}

// SockoptFromContext returns Socket configs in this context, or nil if not contained.
func SockoptFromContext(ctx context.Context) *Sockopt {
	if sockopt, ok := ctx.Value(sockoptSessionKey).(*Sockopt); ok {
		return sockopt
	}
	return nil
}

func GetForcedOutboundTagFromContext(ctx context.Context) string {
	if ContentFromContext(ctx) == nil {
		return ""
	}
	return ContentFromContext(ctx).Attribute("forcedOutboundTag")
}

func SetForcedOutboundTagToContext(ctx context.Context, tag string) context.Context {
	if contentFromContext := ContentFromContext(ctx); contentFromContext == nil {
		ctx = ContextWithContent(ctx, &Content{})
	}
	ContentFromContext(ctx).SetAttribute("forcedOutboundTag", tag)
	return ctx
}

type TrackedRequestErrorFeedback interface {
	SubmitError(err error)
}

func SubmitOutboundErrorToOriginator(ctx context.Context, err error) {
	if errorTracker := ctx.Value(trackedConnectionErrorKey); errorTracker != nil {
		errorTracker := errorTracker.(TrackedRequestErrorFeedback)
		errorTracker.SubmitError(err)
	}
}

func TrackedConnectionError(ctx context.Context, tracker TrackedRequestErrorFeedback) context.Context {
	return context.WithValue(ctx, trackedConnectionErrorKey, tracker)
}

func ContextWithDispatcher(ctx context.Context, dispatcher routing.Dispatcher) context.Context {
	return context.WithValue(ctx, dispatcherKey, dispatcher)
}

func DispatcherFromContext(ctx context.Context) routing.Dispatcher {
	if dispatcher, ok := ctx.Value(dispatcherKey).(routing.Dispatcher); ok {
		return dispatcher
	}
	return nil
}

func ContextWithTimeoutOnly(ctx context.Context, only bool) context.Context {
	return context.WithValue(ctx, timeoutOnlyKey, only)
}

func TimeoutOnlyFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(timeoutOnlyKey).(bool); ok {
		return val
	}
	return false
}

func ContextWithAllowedNetwork(ctx context.Context, network net.Network) context.Context {
	return context.WithValue(ctx, allowedNetworkKey, network)
}

func AllowedNetworkFromContext(ctx context.Context) net.Network {
	if val, ok := ctx.Value(allowedNetworkKey).(net.Network); ok {
		return val
	}
	return net.Network_Unknown
}

func ContextWithMitmAlpn11(ctx context.Context, alpn11 bool) context.Context {
	return context.WithValue(ctx, mitmAlpn11Key, alpn11)
}

func MitmAlpn11FromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(mitmAlpn11Key).(bool); ok {
		return val
	}
	return false
}

func ContextWithMitmServerName(ctx context.Context, serverName string) context.Context {
	return context.WithValue(ctx, mitmServerNameKey, serverName)
}

func MitmServerNameFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(mitmServerNameKey).(string); ok {
		return val
	}
	return ""
}

package log

import (
	"context"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/serial"
)

type logKey int

const (
	accessMessageKey logKey = iota
)

type AccessStatus string

const (
	AccessAccepted = AccessStatus("accepted")
	AccessRejected = AccessStatus("rejected")
)

type AccessMessage struct {
	From   interface{}
	To     interface{}
	Status AccessStatus
	Reason interface{}
	Email  string
	Detour string
	Count  int32
}

func (m *AccessMessage) String() string {
	builder := strings.Builder{}
	builder.WriteString(serial.ToString(m.From))
	builder.WriteByte(' ')
	builder.WriteString(string(m.Status))
	builder.WriteByte(' ')
	builder.WriteString(serial.ToString(m.To))

	if len(m.Detour) > 0 {
		builder.WriteString(" [")
		builder.WriteString(m.Detour)
		builder.WriteByte(']')
	}

	if reason := serial.ToString(m.Reason); len(reason) > 0 {
		builder.WriteString(" ")
		builder.WriteString(reason)
	}

	if len(m.Email) > 0 {
		builder.WriteString(" email: ")
		builder.WriteString(m.Email)
	}

	if m.Count >= 0 {
		builder.WriteString(" count: ")
		builder.WriteString(strconv.Itoa(int(m.Count)))
	}

	return builder.String()
}

func ContextWithAccessMessage(ctx context.Context, accessMessage *AccessMessage) context.Context {
	return context.WithValue(ctx, accessMessageKey, accessMessage)
}

func AccessMessageFromContext(ctx context.Context) *AccessMessage {
	if accessMessage, ok := ctx.Value(accessMessageKey).(*AccessMessage); ok {
		return accessMessage
	}
	return nil
}

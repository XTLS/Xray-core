package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/loopback"
	"google.golang.org/protobuf/proto"
)

type LoopbackConfig struct {
	InboundTag string          `json:"inboundTag"`
	Sniffing   *SniffingConfig `json:"sniffing"`
}

func (l LoopbackConfig) Build() (proto.Message, error) {
	c := &loopback.Config{InboundTag: l.InboundTag}
	if l.Sniffing != nil {
		sc, err := l.Sniffing.Build()
		if err != nil {
			return nil, errors.New("failed to build sniffing config").Base(err)
		}
		c.Sniffing = sc
	}
	return c, nil
}

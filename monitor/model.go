package monitor

import (
	"github.com/xtls/xray-core/common/protocol"
	"time"
)

type Log struct {
	Level     string    `json:"level,omitempty" bson:"level,omitempty"`
	Message   string    `json:"message,omitempty" bson:"message,omitempty"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	Error     string    `json:"error" bson:"error"`
	File      string    `json:"file" bson:"file"`
}

type Destination struct {
	Port               uint16                  `json:"port" bson:"port"`
	Command            protocol.RequestCommand `json:"command" bson:"command"`
	DestinationAddress string                  `json:"destination_address" bson:"destination_address"`
	DestinationPort    uint16                  `json:"destination_port" bson:"destination_port"`
	DestinationDomain  string                  `json:"destination_domain" bson:"destination_domain"`
}

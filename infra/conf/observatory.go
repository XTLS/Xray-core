package conf

import (
	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
	"google.golang.org/protobuf/proto"
)

type ObservatoryConfig struct {
	SubjectSelector   []string          `json:"subjectSelector,omitempty"`
	ProbeURL          string            `json:"probeURL,omitempty"`
	ProbeInterval     duration.Duration `json:"probeInterval,omitempty"`
	EnableConcurrency bool              `json:"enableConcurrency,omitempty"`
}

func (o *ObservatoryConfig) Build() (proto.Message, error) {
	return &observatory.Config{SubjectSelector: o.SubjectSelector, ProbeUrl: o.ProbeURL, ProbeInterval: int64(o.ProbeInterval), EnableConcurrency: o.EnableConcurrency}, nil
}

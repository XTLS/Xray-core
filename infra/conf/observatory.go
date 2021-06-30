package conf

import (
	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/app/observatory"
)

type ObservatoryConfig struct {
	SubjectSelector []string `json:"subjectSelector"`
	ProbeURL        string   `json:"probeURL"`
}

func (o *ObservatoryConfig) Build() (proto.Message, error) {
	return &observatory.Config{SubjectSelector: o.SubjectSelector, ProbeUrl: o.ProbeURL}, nil
}

package observatory

import (
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/extension"
)

type echCollector struct {
	status extension.ECHStatus
}

func newECHCollector() *echCollector {
	return &echCollector{}
}

func (e *echCollector) SubmitECHStatus(status session.OutboundECHStatus) {
	if status.Enabled {
		e.status.Enabled = true
	}
	if status.Accepted {
		e.status.Accepted = true
	}
	if status.ServerName != "" {
		e.status.ServerName = status.ServerName
	}
}

func (e *echCollector) Status() extension.ECHStatus {
	return e.status
}

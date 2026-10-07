package log_test

import (
	"testing"

	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/common/log"
)

func TestMaskedPriorityForwarding(t *testing.T) {
	normal := &log.GeneralMessage{Severity: log.Severity_Info, Content: "masked same"}
	priority := &log.GeneralMessage{Severity: log.Severity_Info, Content: "masked same", Priority: true}
	a := &applog.MaskedMsgWrapper{Message: normal}
	b := &applog.MaskedMsgWrapper{Message: priority}
	if a.IsPriority() || !b.IsPriority() || a.String() != b.String() {
		t.Fatal("masked priority metadata/format")
	}
}

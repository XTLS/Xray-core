package errors_test

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
)

type priorityCapture struct{ rows []*log.GeneralMessage }

func (c *priorityCapture) Handle(msg log.Message) { c.rows = append(c.rows, msg.(*log.GeneralMessage)) }

func TestLogInfoPrioritySeverityAndCallerUnchanged(t *testing.T) {
	c := new(priorityCapture)
	log.RegisterHandler(c)
	defer log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter()))
	errors.LogInfo(context.Background(), "periodic")
	errors.LogInfoPriority(context.Background(), "periodic")
	if len(c.rows) != 2 || c.rows[0].Priority || !c.rows[1].Priority {
		t.Fatal("priority metadata")
	}
	for _, r := range c.rows {
		if r.Severity != log.Severity_Info || !strings.Contains(r.String(), "common/errors_test: periodic") {
			t.Fatal(r.String())
		}
	}
	if c.rows[0].String() != c.rows[1].String() {
		t.Fatal("text changed")
	}
}

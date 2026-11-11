package log_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	"github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
)

type logMessageFunc func() string

func (f logMessageFunc) String() string { return f() }

func TestCloseReleasesLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	t.Cleanup(func() { clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		logger, err := log.New(context.Background(), &log.Config{
			AccessLogType: log.LogType_None,
			ErrorLogType:  log.LogType_File,
			ErrorLogPath:  path,
			ErrorLogLevel: clog.Severity_Debug,
		})
		if err != nil {
			t.Fatal(err)
		}

		entered := make(chan struct{})
		release := make(chan struct{})
		clog.Record(&clog.GeneralMessage{
			Severity: clog.Severity_Debug,
			Content: logMessageFunc(func() string {
				close(entered)
				<-release
				// A message formatter can log while Close waits for the worker.
				clog.Record(&clog.GeneralMessage{Severity: clog.Severity_Debug, Content: "nested message"})
				return "last message"
			}),
		})
		<-entered

		closed := make(chan error, 1)
		go func() { closed <- logger.Close() }()
		synctest.Wait()
		if len(closed) != 0 {
			t.Error("Close returned while the log worker was still active")
		}

		close(release)
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatalf("rename log after Close: %v", err)
		}
	})
}

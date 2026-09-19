package log_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/testing/mocks"
)

func TestCustomLogHandler(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	var loggedValue []string

	mockHandler := mocks.NewLogHandler(mockCtl)
	mockHandler.EXPECT().Handle(gomock.Any()).AnyTimes().DoAndReturn(func(msg clog.Message) {
		loggedValue = append(loggedValue, msg.String())
	})

	log.RegisterHandlerCreator(log.LogType_Console, func(lt log.LogType, options log.HandlerCreatorOptions) (clog.Handler, error) {
		return mockHandler, nil
	})

	logger, err := log.New(context.Background(), &log.Config{
		ErrorLogLevel: clog.Severity_Debug,
		ErrorLogType:  log.LogType_Console,
		AccessLogType: log.LogType_None,
	})
	common.Must(err)
	if !logger.Enabled(clog.Severity_Debug) || len(loggedValue) != 1 || loggedValue[0] != "[Debug] app/log: Logger started" {
		t.Fatalf("unexpected startup state: %v", loggedValue)
	}

	common.Must(logger.Start())

	clog.Record(&clog.GeneralMessage{
		Severity: clog.Severity_Debug,
		Content:  "test",
	})

	if len(loggedValue) < 2 {
		t.Fatal("expected 2 log messages, but actually ", loggedValue)
	}

	if loggedValue[1] != "[Debug] test" {
		t.Fatal("expected '[Debug] test', but actually ", loggedValue[1])
	}

	common.Must(logger.Close())
	count := len(loggedValue)
	if logger.Enabled(clog.Severity_Error) {
		t.Fatal("closed logger is enabled")
	}
	errors.LogError(context.Background(), "closed")
	clog.Record(&clog.GeneralMessage{Severity: clog.Severity_Error, Content: "closed"})
	if len(loggedValue) != count {
		t.Fatal("closed logger handled a message")
	}
	common.Must(logger.Start())
	if !logger.Enabled(clog.Severity_Debug) {
		t.Fatal("restarted logger is disabled")
	}
	errors.LogDebug(context.Background(), "restarted")
	if len(loggedValue) != count+1 || loggedValue[count] != "[Debug] app/log_test: restarted" {
		t.Fatalf("unexpected restart messages: %v", loggedValue[count:])
	}
	common.Must(logger.Close())
}

func TestLogEnabled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		logType log.LogType
	}{
		{"warning", log.LogType_Event},
		{"none", log.LogType_None},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := mocks.NewLogHandler(gomock.NewController(t))
			if tc.logType != log.LogType_None {
				handler.EXPECT().Handle(gomock.Any()).Times(1)
			}
			common.Must(log.RegisterHandlerCreator(log.LogType_Event, func(log.LogType, log.HandlerCreatorOptions) (clog.Handler, error) {
				return handler, nil
			}))
			config := &log.Config{
				ErrorLogType: tc.logType, ErrorLogLevel: clog.Severity_Warning, AccessLogType: log.LogType_None,
			}
			logger, err := log.New(context.Background(), config)
			common.Must(err)
			defer logger.Close()
			for _, severity := range []clog.Severity{clog.Severity_Debug, clog.Severity_Info, clog.Severity_Warning, clog.Severity_Error, clog.Severity_Unknown, -1} {
				want := tc.logType != log.LogType_None && severity <= clog.Severity_Warning
				if logger.Enabled(severity) != want || clog.Enabled(severity) != want {
					t.Fatalf("Enabled(%v) != %v", severity, want)
				}
			}
			// Direct records still need the final check in Handle.
			clog.Record(&clog.GeneralMessage{Severity: clog.Severity_Debug, Content: "disabled"})
			clog.Record(&clog.GeneralMessage{Severity: clog.Severity_Warning, Content: "warning"})
			common.Must(logger.Close())
			if clog.Enabled(-1) {
				t.Fatal("closed logger is enabled")
			}
			config.ErrorLogLevel = clog.Severity_Error
			common.Must(logger.Start())
			if clog.Enabled(clog.Severity_Warning) || clog.Enabled(clog.Severity_Error) != (tc.logType != log.LogType_None) {
				t.Fatal("restarted logger did not pick up the new level")
			}
		})
	}
}

func TestLogConcurrentRestart(t *testing.T) {
	common.Must(log.RegisterHandlerCreator(log.LogType_Event, func(log.LogType, log.HandlerCreatorOptions) (clog.Handler, error) {
		return discardHandler{}, nil
	}))
	logger, err := log.New(context.Background(), &log.Config{
		ErrorLogType: log.LogType_Event, ErrorLogLevel: clog.Severity_Warning, AccessLogType: log.LogType_None,
	})
	common.Must(err)
	defer logger.Close()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			errors.LogError(context.Background(), "message")
		}
	})
	for range 1000 {
		common.Must(logger.Close())
		common.Must(logger.Start())
	}
	wg.Wait()
}

func TestLogEnabledDuringStart(t *testing.T) {
	starting, resume := make(chan struct{}), make(chan struct{})
	common.Must(log.RegisterHandlerCreator(log.LogType_Event, func(log.LogType, log.HandlerCreatorOptions) (clog.Handler, error) {
		close(starting)
		<-resume
		return discardHandler{}, nil
	}))
	started := make(chan *log.Instance, 1)
	go func() {
		logger, err := log.New(context.Background(), &log.Config{
			ErrorLogType: log.LogType_Event, ErrorLogLevel: clog.Severity_Warning, AccessLogType: log.LogType_None,
		})
		common.Must(err)
		started <- logger
	}()
	<-starting
	enabled := make(chan bool, 1)
	go func() { enabled <- clog.Enabled(clog.Severity_Error) }()
	select {
	case ok := <-enabled:
		if !ok {
			t.Error("logs during startup must reach the final check in Handle")
		}
	case <-time.After(time.Second):
		t.Error("Enabled blocked on logger startup")
	}
	close(resume)
	common.Must((<-started).Close())
}

func TestLogEnabledAfterStartFailure(t *testing.T) {
	_, err := log.New(context.Background(), &log.Config{
		ErrorLogType: log.LogType_File, ErrorLogLevel: clog.Severity_Debug, ErrorLogPath: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected an error opening a directory as a log file")
	}
	if clog.Enabled(-1) {
		t.Fatal("failed logger is enabled")
	}
}

func TestMaskAddress(t *testing.T) {
	m4, m6, err := log.ParseMaskAddress("half")
	if err != nil {
		t.Fatal(err)
	}
	maskedAddr := log.MaskedMsgWrapper{
		Mask4: m4,
		Mask6: m6,
	}
	maskedAddr.Message = net.ParseIP("11.45.1.4")
	if maskedAddr.String() != "11.45.*.*" {
		t.Fatal("expected '11.45.*.*', but actually ", maskedAddr.String())
	}
	maskedAddr.Message = net.ParseIP("11:45:14:19:19:81:0::")
	if maskedAddr.String() != "11:45::/32" {
		t.Fatal("expected '11:45::/32', but actually", maskedAddr.String())
	}

	m4, m6, err = log.ParseMaskAddress("/16+/64")
	if err != nil {
		t.Fatal(err)
	}
	maskedAddr = log.MaskedMsgWrapper{
		Mask4: m4,
		Mask6: m6,
	}
	maskedAddr.Message = net.ParseIP("11.45.1.4")
	if maskedAddr.String() != "11.45.*.*" {
		t.Fatal("expected '11.45.*.*', but actually ", maskedAddr.String())
	}
	maskedAddr.Message = net.ParseIP("11:45:14:19:19:81:0::")
	if maskedAddr.String() != "11:45:14:19::/64" {
		t.Fatal("expected '11:45:14:19::/64', but actually", maskedAddr.String())
	}
}

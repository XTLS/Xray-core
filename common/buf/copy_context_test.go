package buf_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/testing/mocks"
)

func TestCopyContextCancel(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockReader := mocks.NewReader(mockCtl)
	mockReader.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
		time.Sleep(200 * time.Millisecond)
		return 0, io.EOF
	}).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := CopyContext(ctx, NewReader(mockReader), Discard)
	if err == nil {
		t.Fatal("expected context error")
	}
}

func BenchmarkCopyContext(b *testing.B) {
	reader := NewReader(io.LimitReader(TestReader{}, 10240))
	writer := Discard
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CopyContext(ctx, reader, writer)
	}
}

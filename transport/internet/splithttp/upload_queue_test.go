package splithttp_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

func Test_regression_readzero(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{
		Payload: []byte("x"),
		Seq:     0,
	})
	buf := make([]byte, 20)
	n, err := q.Read(buf)
	common.Must(err)
	if n != 1 {
		t.Error("n=", n)
	}
}

func Test_regression_max_packets(t *testing.T) {
	q := NewUploadQueue(2)

	go func() {
		q.Push(Packet{Payload: []byte("x"), Seq: 1})
		q.Push(Packet{Payload: []byte("y"), Seq: 2})
		q.Push(Packet{Payload: []byte("z"), Seq: 3})
	}()

	buf := make([]byte, 20)

	_, err := q.Read(buf)
	if err == nil {
		t.Error("expected error, got nil")
	} else if !strings.Contains(err.Error(), "packet queue is too large") {
		t.Error("expected 'packet queue is too large' error, got:", err)
	}
}

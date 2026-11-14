package errors_test

import (
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/common/errors"
)

func TestError(t *testing.T) {
	err := New("TestError")
	if v := err.Error(); !strings.Contains(v, "TestError") {
		t.Error("error: ", v)
	}

	err = New("TestError2").Base(io.EOF)
	if v := err.Error(); !strings.Contains(v, "EOF") {
		t.Error("error: ", v)
	}

	err = New("TestError3").Base(io.EOF)
	err = New("TestError4").Base(err)
	if v := err.Error(); !strings.Contains(v, "EOF") {
		t.Error("error: ", v)
	}
}

func TestErrorMessage(t *testing.T) {
	data := []struct {
		err error
		msg string
	}{
		{
			err: New("a").Base(New("b")),
			msg: "common/errors_test: a > common/errors_test: b",
		},
	}

	for _, d := range data {
		if diff := cmp.Diff(d.msg, d.err.Error()); diff != "" {
			t.Error(diff)
		}
	}
}

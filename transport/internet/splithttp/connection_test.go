package splithttp

import "testing"

func TestSplitConnJoinSize(t *testing.T) {
	if (&splitConn{}).JoinSize() == 0 || (&splitConn{writer: uploadWriter{}}).JoinSize() != 0 {
		t.Error("only what uploads in packets does not have its Buffers joined")
	}
}

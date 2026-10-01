package quic_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
)

func TestSniffQUICZeroPaddedDatagrams(t *testing.T) {
	data, err := os.ReadFile("testdata/zero_padded_datagrams.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ExpectedDomain string   `json:"expected_domain"`
		Datagrams      []string `json:"datagrams"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Datagrams) != 2 {
		t.Fatalf("got %d datagrams, want 2", len(fixture.Datagrams))
	}

	var payload []byte
	for i, encoded := range fixture.Datagrams {
		datagram, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode datagram %d: %v", i, err)
		}
		payload = append(payload, datagram...)

		header, err := quic.SniffQUIC(append([]byte(nil), payload...))
		if i == 0 {
			if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
				t.Fatalf("first datagram error = %v, want ErrProtoNeedMoreData", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Domain() != fixture.ExpectedDomain {
			t.Fatalf("domain = %q, want %q", header.Domain(), fixture.ExpectedDomain)
		}
	}
}

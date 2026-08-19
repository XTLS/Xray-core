package rawpacket

import (
	"net/netip"
	"testing"
)

func TestTCPSimStateClient(t *testing.T) {
	st := newTCPSimState()
	if st.clientFlags() != TCPFlagSyn {
		t.Fatalf("first client segment should be SYN, got %#x", st.clientFlags())
	}
	seq := st.nextSeq(100)
	if seq != st.isn {
		t.Fatalf("first data seq should be ISN, got %d want %d", seq, st.isn)
	}
	if st.clientFlags() != TCPFlagAck {
		t.Fatalf("second client segment should be ACK, got %#x", st.clientFlags())
	}
	if got := st.ack(); got != 0 {
		t.Fatalf("ack before observing peer should be 0, got %d", got)
	}
	// peer handshake: SYN consumes one byte, then 500 bytes of data
	st.observePeer(1000, 0)
	if st.ack() != 1001 {
		t.Fatalf("ack after peer SYN should be seq+1, got %d want 1001", st.ack())
	}
	st.observePeer(1001, 500)
	if st.ack() != 1501 {
		t.Fatalf("ack should be peer seq+len+1, got %d want 1501", st.ack())
	}
	// zero-length segments (keepalives) must not advance the sequence
	if st.nextSeq(0) != st.isn+100 {
		t.Fatalf("zero-length segment advanced seq: got %d want %d", st.nextSeq(0), st.isn+100)
	}
	// nextSeq returns the segment's own seq (pre-advance)
	if got := st.nextSeq(10); got != st.isn+100 {
		t.Fatalf("data after keepalive should be isn+100, got %d", got)
	}
	if got := st.nextSeq(1); got != st.isn+110 {
		t.Fatalf("next segment should be isn+110, got %d", got)
	}
}

func TestTCPSimStateServer(t *testing.T) {
	st := newTCPSimState()
	if st.serverFlags() != TCPFlagSyn|TCPFlagAck {
		t.Fatalf("first server segment should be SYN|ACK, got %#x", st.serverFlags())
	}
	if st.serverFlags() != TCPFlagAck {
		t.Fatalf("second server segment should be ACK, got %#x", st.serverFlags())
	}
	st.observeClientSeq(777)
	if st.ack() != 778 {
		t.Fatalf("server ack should be observed client seq+1, got %d want 778", st.ack())
	}
	seq := st.nextSeq(50)
	if seq != st.isn {
		t.Fatalf("server data should start at its ISN, got %d", seq)
	}
	if got := st.nextSeq(30); got != st.isn+50 {
		t.Fatalf("server second segment should be isn+50, got %d", got)
	}
}

func TestBuildTCPPacketOptionsAndFlags(t *testing.T) {
	src := netip.MustParseAddr("1.2.3.4")
	dst := netip.MustParseAddr("5.6.7.8")
	st := newTCPSimState()

	// SYN segment: 20 ip + 20 tcp + 20 options
	syn := BuildTCPPacket(src, dst, 12345, 443, st.isn, 0, TCPFlagSyn, nil, 64, 100, true)
	if len(syn) != 20+40 {
		t.Fatalf("SYN should be 60 bytes (20 ip + 40 tcp w/ 20 opts), got %d", len(syn))
	}
	if syn[0]>>4 != 4 {
		t.Fatalf("not IPv4: %#x", syn[0])
	}
	// DF bit set
	if syn[6]&0x40 == 0 {
		t.Fatal("DF bit not set")
	}
	// IP ID
	if id := uint16(syn[4])<<8 | uint16(syn[5]); id != 100 {
		t.Fatalf("IP ID = %d, want 100", id)
	}
	// data offset: 40 bytes tcp => 10 words
	if syn[32]>>4 != 10 {
		t.Fatalf("TCP data offset = %d, want 10", syn[32]>>4)
	}
	// MSS option at offset 20
	if syn[40] != 2 || syn[41] != 4 {
		t.Fatal("MSS option kind not found")
	}
	if mss := uint16(syn[42])<<8 | uint16(syn[43]); mss != tcpMaxSegmentMSS {
		t.Fatalf("MSS = %d, want %d", mss, tcpMaxSegmentMSS)
	}
	// checksum sanity: valid checksum means header verifies
	checkTCPChecksum(t, syn)

	// data segment: ACK only, 12-byte options
	payload := make([]byte, 100)
	data := BuildTCPPacket(src, dst, 12345, 443, st.isn, 1000, TCPFlagAck, payload, 64, 101, false)
	if len(data) != 20+32+100 {
		t.Fatalf("data seg should be 152 bytes, got %d", len(data))
	}
	if data[32]>>4 != 8 {
		t.Fatalf("data offset = %d, want 8", data[32]>>4)
	}
	if data[40] != 1 || data[41] != 1 || data[42] != 8 || data[43] != 10 {
		t.Fatal("data segment should carry NOP NOP TS options")
	}
	checkTCPChecksum(t, data)
}

func checkTCPChecksum(t *testing.T, pkt []byte) {
	t.Helper()
	pseudo := IPv4PseudoHeaderChecksum(
		netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}),
		netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}),
		pkt[9],
		uint16(len(pkt)-20),
	)
	if csum := Checksum(pkt[20:], pseudo); csum != 0xffff {
		t.Fatalf("TCP checksum invalid: %#x", csum)
	}
}

func TestMaxPayloadForMTU(t *testing.T) {
	if got := maxPayloadForMTU(0); got != frameMaxPayload {
		t.Fatalf("default should be frameMaxPayload, got %d", got)
	}
	if got := maxPayloadForMTU(1500); got != 1500-20-40-frameOverhead {
		t.Fatalf("1500 MTU: got %d", got)
	}
	if got := maxPayloadForMTU(100); got < 1 {
		t.Fatalf("tiny MTU should clamp to >= 1, got %d", got)
	}
	if got := maxPayloadForMTU(1 << 20); got != frameMaxPayload {
		t.Fatalf("huge MTU should cap at frameMaxPayload, got %d", got)
	}
}

func TestBuildTCPPacketIPIDMonotonic(t *testing.T) {
	src := netip.MustParseAddr("1.2.3.4")
	dst := netip.MustParseAddr("5.6.7.8")
	prev := uint16(65000)
	for i := 0; i < 100; i++ {
		prev++
		pkt := BuildTCPPacket(src, dst, 1, 443, 1, 1, TCPFlagAck, nil, 64, prev, false)
		if id := uint16(pkt[4])<<8 | uint16(pkt[5]); id != prev {
			t.Fatalf("IP ID = %d, want %d", id, prev)
		}
	}
}

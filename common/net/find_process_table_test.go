package net

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestTransportTableSearcherFindsSynSentTCPRow(t *testing.T) {
	table := transportTable(
		tcp4Row(3, [4]byte{172, 18, 0, 1}, 20543, [4]byte{175, 4, 62, 127}, 443, 8480),
	)

	pid, err := newSearcher(Network_TCP, AddressFamilyIPv4).Search(
		table,
		netip.MustParseAddr("172.18.0.1"),
		20543,
		netip.MustParseAddr("175.4.62.127"),
		443,
	)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 8480 {
		t.Fatalf("pid = %d, want 8480", pid)
	}
}

func TestTransportTableSearcherMatchesTCPRemoteEndpoint(t *testing.T) {
	table := transportTable(
		tcp4Row(5, [4]byte{172, 18, 0, 1}, 20543, [4]byte{203, 0, 113, 1}, 443, 1111),
		tcp4Row(3, [4]byte{172, 18, 0, 1}, 20543, [4]byte{175, 4, 62, 127}, 443, 2222),
	)

	pid, err := newSearcher(Network_TCP, AddressFamilyIPv4).Search(
		table,
		netip.MustParseAddr("172.18.0.1"),
		20543,
		netip.MustParseAddr("175.4.62.127"),
		443,
	)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 2222 {
		t.Fatalf("pid = %d, want 2222", pid)
	}
}

func TestTransportTableSearcherAllowsUnspecifiedUDPAddress(t *testing.T) {
	table := transportTable(udp4Row([4]byte{0, 0, 0, 0}, 49330, 1234))

	pid, err := newSearcher(Network_UDP, AddressFamilyIPv4).Search(
		table,
		netip.MustParseAddr("172.18.0.1"),
		49330,
		netip.Addr{},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 1234 {
		t.Fatalf("pid = %d, want 1234", pid)
	}
}

func transportTable(rows ...[]byte) []byte {
	size := 4
	for _, row := range rows {
		size += len(row)
	}
	table := make([]byte, size)
	binary.LittleEndian.PutUint32(table[:4], uint32(len(rows)))
	offset := 4
	for _, row := range rows {
		copy(table[offset:], row)
		offset += len(row)
	}
	return table
}

func tcp4Row(state uint32, localIP [4]byte, localPort uint16, remoteIP [4]byte, remotePort uint16, pid uint32) []byte {
	row := make([]byte, 24)
	binary.LittleEndian.PutUint32(row[0:4], state)
	copy(row[4:8], localIP[:])
	binary.BigEndian.PutUint16(row[8:10], localPort)
	copy(row[12:16], remoteIP[:])
	binary.BigEndian.PutUint16(row[16:18], remotePort)
	binary.LittleEndian.PutUint32(row[20:24], pid)
	return row
}

func udp4Row(localIP [4]byte, localPort uint16, pid uint32) []byte {
	row := make([]byte, 12)
	copy(row[0:4], localIP[:])
	binary.BigEndian.PutUint16(row[4:6], localPort)
	binary.LittleEndian.PutUint32(row[8:12], pid)
	return row
}

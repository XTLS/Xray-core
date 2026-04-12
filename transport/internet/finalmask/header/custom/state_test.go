package custom

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func mustSendRecvUDP(t *testing.T, from net.PacketConn, to net.PacketConn, msg []byte) {
	t.Helper()

	go func() {
		_, err := from.WriteTo(msg, to.LocalAddr())
		if err != nil {
			t.Error(err)
		}
	}()

	buf := make([]byte, 1024)
	n, _, err := to.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatalf("unexpected size: %d", n)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
}

func TestStateUDPResponseReusesPriorCapturedValues(t *testing.T) {
	cfg := &UDPConfig{
		Client: []*UDPItem{
			{
				Rand:    2,
				RandMin: 0x2A,
				RandMax: 0x2A,
				Save:    "txid",
			},
		},
		Server: []*UDPItem{
			{
				Var: "txid",
			},
		},
	}
	maskManager := finalmask.NewUdpmaskManager([]finalmask.Udpmask{cfg})

	clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()

	serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()

	client, err := maskManager.WrapPacketConnClient(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	server, err := maskManager.WrapPacketConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))

	mustSendRecvUDP(t, client, server, []byte("client->server"))
	mustSendRecvUDP(t, server, client, []byte("server->client"))
}

func TestStateStoreIsolatesKeys(t *testing.T) {
	store := newStateStore(5 * time.Second)
	store.set("a", map[string][]byte{"txid": {0x01}})
	store.set("b", map[string][]byte{"txid": {0x02}})

	varsA, ok := store.get("a")
	if !ok || len(varsA["txid"]) != 1 || varsA["txid"][0] != 0x01 {
		t.Fatalf("unexpected vars for key a: %v", varsA)
	}
	varsB, ok := store.get("b")
	if !ok || len(varsB["txid"]) != 1 || varsB["txid"][0] != 0x02 {
		t.Fatalf("unexpected vars for key b: %v", varsB)
	}
}

func TestStateStoreExpiresEntries(t *testing.T) {
	store := newStateStore(10 * time.Millisecond)
	store.set("a", map[string][]byte{"txid": {0x01}})

	time.Sleep(20 * time.Millisecond)

	if _, ok := store.get("a"); ok {
		t.Fatal("expected expired state entry to be removed")
	}
}

package socks_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func TestUDPAssociateInboundStats(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("stats=%v", enabled), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			config := fmt.Sprintf(`{"inbounds":[{"tag":"client","listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"protocol":"freedom"}],"stats":{},"policy":{"system":{"statsInboundUplink":%t,"statsInboundDownlink":%t}}}`, port, enabled, enabled)
			instance, err := core.StartInstance("json", []byte(config))
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			manager := instance.GetFeature(stats.ManagerType()).(stats.Manager)
			readStats := func() [2]int64 {
				var result [2]int64
				for i, direction := range []string{"uplink", "downlink"} {
					if counter := manager.GetCounter("inbound>>>client>>>traffic>>>" + direction); counter != nil {
						result[i] = counter.Value()
					}
				}
				return result
			}
			assertStats := func(want [2]int64) {
				t.Helper()
				deadline := time.Now().Add(time.Second)
				for readStats() != want && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if got := readStats(); got != want {
					t.Fatalf("stats = %v, want %v", got, want)
				}
			}
			udpSocket := func() *net.UDPConn {
				t.Helper()
				socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { socket.Close() })
				if err := socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				return socket
			}
			client, peer, foreign := udpSocket(), udpSocket(), udpSocket()
			control, err := net.DialTimeout("tcp4", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			if err := control.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := control.Write([]byte{5, 1, 0}); err != nil || n != 3 {
				t.Fatalf("greeting write length = %d, error = %v", n, err)
			}
			greeting := make([]byte, 2)
			if _, err := io.ReadFull(control, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
				t.Fatalf("greeting = %v, error = %v", greeting, err)
			}
			request := []byte{5, 3, 0, 1, 127, 0, 0, 1, 0, 0}
			binary.BigEndian.PutUint16(request[8:], uint16(client.LocalAddr().(*net.UDPAddr).Port))
			if n, err := control.Write(request); err != nil || n != len(request) {
				t.Fatalf("association write length = %d, error = %v", n, err)
			}
			reply := make([]byte, 10)
			if _, err := io.ReadFull(control, reply); err != nil || reply[1] != 0 || reply[3] != 1 {
				t.Fatalf("association = %v, error = %v", reply, err)
			}
			relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}
			baseline := [2]int64{}
			if enabled {
				baseline = [2]int64{13, 12}
			}
			assertStats(baseline)
			header := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
			binary.BigEndian.PutUint16(header[8:], uint16(peer.LocalAddr().(*net.UDPAddr).Port))
			upload, download := bytes.Repeat([]byte{42}, 1200), bytes.Repeat([]byte{43}, 700)
			foreignPacket := append(append([]byte{}, header...), []byte("foreign")...)
			if n, err := foreign.WriteToUDP(foreignPacket, relay); err != nil || n != len(foreignPacket) {
				t.Fatalf("foreign datagram length = %d, error = %v", n, err)
			}
			for exchange := int64(1); exchange <= 2; exchange++ {
				packet := append(append([]byte{}, header...), upload...)
				if n, err := client.WriteToUDP(packet, relay); err != nil || n != len(packet) {
					t.Fatalf("client datagram length = %d, error = %v", n, err)
				}
				buffer := make([]byte, 2048)
				n, remote, err := peer.ReadFromUDP(buffer)
				if err != nil || !bytes.Equal(buffer[:n], upload) {
					t.Fatalf("upload length = %d, error = %v", n, err)
				}
				if n, err := peer.WriteToUDP(download, remote); err != nil || n != len(download) {
					t.Fatalf("peer datagram length = %d, error = %v", n, err)
				}
				n, _, err = client.ReadFromUDP(buffer)
				if err != nil || !bytes.Equal(buffer[:n], append(append([]byte{}, header...), download...)) {
					t.Fatalf("download length = %d, error = %v", n, err)
				}
				want := baseline
				if enabled {
					want[0] += exchange * 1210
					want[1] += exchange * 710
				}
				assertStats(want)
			}
		})
	}
}

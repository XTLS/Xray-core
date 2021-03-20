package command_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/xtls/xray-core/app/router"
	. "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/testing/mocks"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

func TestServiceSubscribeRoutingStats(t *testing.T) {
	c := stats.NewChannel(&stats.ChannelConfig{
		SubscriberLimit: 1,
		BufferSize:      0,
		Blocking:        true,
	})
	common.Must(c.Start())
	defer c.Close()

	lis := bufconn.Listen(1024 * 1024)
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	testCases := []*RoutingContext{
		{InboundTag: "in", OutboundTag: "out"},
		{TargetIPs: [][]byte{{1, 2, 3, 4}}, TargetPort: 8080, OutboundTag: "out"},
		{TargetDomain: "example.com", TargetPort: 443, OutboundTag: "out"},
		{SourcePort: 9999, TargetPort: 9999, OutboundTag: "out"},
		{Network: net.Network_UDP, OutboundGroupTags: []string{"outergroup", "innergroup"}, OutboundTag: "out"},
		{Protocol: "bittorrent", OutboundTag: "blocked"},
		{User: "example@example.com", OutboundTag: "out"},
		{SourceIPs: [][]byte{{127, 0, 0, 1}}, Attributes: map[string]string{"attr": "value"}, OutboundTag: "out"},
	}
	errCh := make(chan error)
	nextPub := make(chan struct{})

	// Server goroutine
	go func() {
		server := grpc.NewServer()
		RegisterRoutingServiceServer(server, NewRoutingServer(nil, c))
		errCh <- server.Serve(lis)
	}()

	// Publisher goroutine
	go func() {
		publishTestCases := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			for { // Wait until there's one subscriber in routing stats channel
				if len(c.Subscribers()) > 0 {
					break
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
			}
			for _, tc := range testCases {
				c.Publish(context.Background(), AsRoutingRoute(tc))
				time.Sleep(time.Millisecond)
			}
			return nil
		}

		if err := publishTestCases(); err != nil {
			errCh <- err
		}

		// Wait for next round of publishing
		<-nextPub

		if err := publishTestCases(); err != nil {
			errCh <- err
		}
	}()

	// Client goroutine
	go func() {
		defer lis.Close()
		conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		client := NewRoutingServiceClient(conn)

		// Test retrieving all fields
		testRetrievingAllFields := func() error {
			streamCtx, streamClose := context.WithCancel(context.Background())

			// Test the unsubscription of stream works well
			defer func() {
				streamClose()
				timeOutCtx, timeout := context.WithTimeout(context.Background(), time.Second)
				defer timeout()
				for { // Wait until there's no subscriber in routing stats channel
					if len(c.Subscribers()) == 0 {
						break
					}
					if timeOutCtx.Err() != nil {
						t.Error("unexpected subscribers not decreased in channel", timeOutCtx.Err())
					}
				}
			}()

			stream, err := client.SubscribeRoutingStats(streamCtx, &SubscribeRoutingStatsRequest{})
			if err != nil {
				return err
			}

			for _, tc := range testCases {
				msg, err := stream.Recv()
				if err != nil {
					return err
				}
				if r := cmp.Diff(msg, tc, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
			}

			// Test that double subscription will fail
			errStream, err := client.SubscribeRoutingStats(context.Background(), &SubscribeRoutingStatsRequest{
				FieldSelectors: []string{"ip", "port", "domain", "outbound"},
			})
			if err != nil {
				return err
			}
			if _, err := errStream.Recv(); err == nil {
				t.Error("unexpected successful subscription")
			}

			return nil
		}

		// Test retrieving only a subset of fields
		testRetrievingSubsetOfFields := func() error {
			streamCtx, streamClose := context.WithCancel(context.Background())
			defer streamClose()
			stream, err := client.SubscribeRoutingStats(streamCtx, &SubscribeRoutingStatsRequest{
				FieldSelectors: []string{"ip", "port", "domain", "outbound"},
			})
			if err != nil {
				return err
			}

			// Send nextPub signal to start next round of publishing
			close(nextPub)

			for _, tc := range testCases {
				msg, err := stream.Recv()
				if err != nil {
					return err
				}
				stat := &RoutingContext{ // Only a subset of stats is retrieved
					SourceIPs:         tc.SourceIPs,
					TargetIPs:         tc.TargetIPs,
					SourcePort:        tc.SourcePort,
					TargetPort:        tc.TargetPort,
					TargetDomain:      tc.TargetDomain,
					OutboundGroupTags: tc.OutboundGroupTags,
					OutboundTag:       tc.OutboundTag,
				}
				if r := cmp.Diff(msg, stat, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
			}

			return nil
		}

		if err := testRetrievingAllFields(); err != nil {
			errCh <- err
		}
		if err := testRetrievingSubsetOfFields(); err != nil {
			errCh <- err
		}
		errCh <- nil // Client passed all tests successfully
	}()

	// Wait for goroutines to complete
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("Test timeout after 2s")
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceTestRoute(t *testing.T) {
	c := stats.NewChannel(&stats.ChannelConfig{
		SubscriberLimit: 1,
		BufferSize:      16,
		Blocking:        true,
	})
	common.Must(c.Start())
	defer c.Close()

	r := new(router.Router)
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	common.Must(r.Init(&router.Config{
		Rule: []*router.RoutingRule{
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				Networks:  []net.Network{net.Network_UDP, net.Network_TCP},
				Protocol:  []string{"bittorrent"},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "blocked"},
			},
			{
				PortList:  &net.PortList{Range: []*net.PortRange{{From: 8080, To: 8080}}},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				SourcePortList: &net.PortList{Range: []*net.PortRange{{From: 9999, To: 9999}}},
				TargetTag:      &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				Domain:    []*router.Domain{{Type: router.Domain_Domain, Value: "com"}},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				SourceGeoip: []*router.GeoIP{{CountryCode: "private", Cidr: []*router.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}}}},
				TargetTag:   &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				UserEmail: []string{"example@example.com"},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				Networks:  []net.Network{net.Network_TCP},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
		},
	}, mocks.NewDNSClient(mockCtl), mocks.NewOutboundManager(mockCtl)))

	lis := bufconn.Listen(1024 * 1024)
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	errCh := make(chan error)

	// Server goroutine
	go func() {
		server := grpc.NewServer()
		RegisterRoutingServiceServer(server, NewRoutingServer(r, c))
		errCh <- server.Serve(lis)
	}()

	// Client goroutine
	go func() {
		defer lis.Close()
		conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
		if err != nil {
			errCh <- err
		}
		defer conn.Close()
		client := NewRoutingServiceClient(conn)

		testCases := []*RoutingContext{
			{InboundTag: "in", OutboundTag: "out"},
			{TargetIPs: [][]byte{{1, 2, 3, 4}}, TargetPort: 8080, OutboundTag: "out"},
			{TargetDomain: "example.com", TargetPort: 443, OutboundTag: "out"},
			{SourcePort: 9999, TargetPort: 9999, OutboundTag: "out"},
			{Network: net.Network_UDP, Protocol: "bittorrent", OutboundTag: "blocked"},
			{User: "example@example.com", OutboundTag: "out"},
			{SourceIPs: [][]byte{{127, 0, 0, 1}}, Attributes: map[string]string{"attr": "value"}, OutboundTag: "out"},
		}

		// Test simple TestRoute
		testSimple := func() error {
			for _, tc := range testCases {
				route, err := client.TestRoute(context.Background(), &TestRouteRequest{RoutingContext: tc})
				if err != nil {
					return err
				}
				if r := cmp.Diff(route, tc, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
			}
			return nil
		}

		// Test TestRoute with special options
		testOptions := func() error {
			sub, err := c.Subscribe()
			if err != nil {
				return err
			}
			for _, tc := range testCases {
				route, err := client.TestRoute(context.Background(), &TestRouteRequest{
					RoutingContext: tc,
					FieldSelectors: []string{"ip", "port", "domain", "outbound"},
					PublishResult:  true,
				})
				if err != nil {
					return err
				}
				stat := &RoutingContext{ // Only a subset of stats is retrieved
					SourceIPs:         tc.SourceIPs,
					TargetIPs:         tc.TargetIPs,
					SourcePort:        tc.SourcePort,
					TargetPort:        tc.TargetPort,
					TargetDomain:      tc.TargetDomain,
					OutboundGroupTags: tc.OutboundGroupTags,
					OutboundTag:       tc.OutboundTag,
				}
				if r := cmp.Diff(route, stat, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
				select { // Check that routing result has been published to statistics channel
				case msg, received := <-sub:
					if route, ok := msg.(routing.Route); received && ok {
						if r := cmp.Diff(AsProtobufMessage(nil)(route), tc, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
							t.Error(r)
						}
					} else {
						t.Error("unexpected failure in receiving published routing result for testcase", tc)
					}
				case <-time.After(100 * time.Millisecond):
					t.Error("unexpected failure in receiving published routing result", tc)
				}
			}
			return nil
		}

		if err := testSimple(); err != nil {
			errCh <- err
		}
		if err := testOptions(); err != nil {
			errCh <- err
		}
		errCh <- nil // Client passed all tests successfully
	}()

	// Wait for goroutines to complete
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("Test timeout after 2s")
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceAddRoutingRule(t *testing.T) {
	c := stats.NewChannel(&stats.ChannelConfig{
		SubscriberLimit: 1,
		BufferSize:      16,
		Blocking:        true,
	})
	common.Must(c.Start())
	defer c.Close()

	r := new(router.Router)
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	common.Must(r.Init(&router.Config{}, mocks.NewDNSClient(mockCtl), mocks.NewOutboundManager(mockCtl)))

	lis := bufconn.Listen(1024 * 1024)
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	errCh := make(chan error)

	// Server goroutine
	go func() {
		server := grpc.NewServer()
		RegisterRoutingServiceServer(server, NewRoutingServer(r, c))
		errCh <- server.Serve(lis)
	}()

	// Client goroutine
	go func() {
		defer lis.Close()
		conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
		if err != nil {
			errCh <- err
		}
		defer conn.Close()
		client := NewRoutingServiceClient(conn)

		testAddRuleCases := []*router.RoutingRule{
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				Networks:  []net.Network{net.Network_UDP, net.Network_TCP},
				Protocol:  []string{"bittorrent"},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "blocked"},
			},
			{
				PortList:  &net.PortList{Range: []*net.PortRange{{From: 8080, To: 8080}}},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				SourcePortList: &net.PortList{Range: []*net.PortRange{{From: 9999, To: 9999}}},
				TargetTag:      &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				Domain:    []*router.Domain{{Type: router.Domain_Domain, Value: "com"}},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				SourceGeoip: []*router.GeoIP{{CountryCode: "private", Cidr: []*router.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}}}},
				TargetTag:   &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				UserEmail: []string{"example@example.com"},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
			{
				Networks:  []net.Network{net.Network_TCP},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
			},
		}

		// Test add rule
		testAddRule := func() error {
			for _, tc := range testAddRuleCases {
				_, err := client.AddRoutingRule(context.Background(), &AddRoutingRuleRequest{RoutingRule: tc})
				if err != nil {
					return err
				}
			}
			return nil
		}

		testCases := []*RoutingContext{
			{InboundTag: "in", OutboundTag: "out"},
			{TargetIPs: [][]byte{{1, 2, 3, 4}}, TargetPort: 8080, OutboundTag: "out"},
			{TargetDomain: "example.com", TargetPort: 443, OutboundTag: "out"},
			{SourcePort: 9999, TargetPort: 9999, OutboundTag: "out"},
			{Network: net.Network_UDP, Protocol: "bittorrent", OutboundTag: "blocked"},
			{User: "example@example.com", OutboundTag: "out"},
			{SourceIPs: [][]byte{{127, 0, 0, 1}}, Attributes: map[string]string{"attr": "value"}, OutboundTag: "out"},
		}

		// Test simple TestRoute
		testSimple := func() error {
			for _, tc := range testCases {
				route, err := client.TestRoute(context.Background(), &TestRouteRequest{RoutingContext: tc})
				if err != nil {
					return err
				}
				if r := cmp.Diff(route, tc, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
			}
			return nil
		}

		// Test TestRoute with special options
		testOptions := func() error {
			sub, err := c.Subscribe()
			if err != nil {
				return err
			}
			for _, tc := range testCases {
				route, err := client.TestRoute(context.Background(), &TestRouteRequest{
					RoutingContext: tc,
					FieldSelectors: []string{"ip", "port", "domain", "outbound"},
					PublishResult:  true,
				})
				if err != nil {
					return err
				}
				stat := &RoutingContext{ // Only a subset of stats is retrieved
					SourceIPs:         tc.SourceIPs,
					TargetIPs:         tc.TargetIPs,
					SourcePort:        tc.SourcePort,
					TargetPort:        tc.TargetPort,
					TargetDomain:      tc.TargetDomain,
					OutboundGroupTags: tc.OutboundGroupTags,
					OutboundTag:       tc.OutboundTag,
				}
				if r := cmp.Diff(route, stat, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
				select { // Check that routing result has been published to statistics channel
				case msg, received := <-sub:
					if route, ok := msg.(routing.Route); received && ok {
						if r := cmp.Diff(AsProtobufMessage(nil)(route), tc, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
							t.Error(r)
						}
					} else {
						t.Error("unexpected failure in receiving published routing result for testcase", tc)
					}
				case <-time.After(100 * time.Millisecond):
					t.Error("unexpected failure in receiving published routing result", tc)
				}
			}
			return nil
		}

		if err := testAddRule(); err != nil {
			errCh <- err
		}
		if err := testSimple(); err != nil {
			errCh <- err
		}
		if err := testOptions(); err != nil {
			errCh <- err
		}
		errCh <- nil // Client passed all tests successfully
	}()

	// Wait for goroutines to complete
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("Test timeout after 2s")
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceAlterRoutingRule(t *testing.T) {
	c := stats.NewChannel(&stats.ChannelConfig{
		SubscriberLimit: 1,
		BufferSize:      16,
		Blocking:        true,
	})
	common.Must(c.Start())
	defer c.Close()

	r := new(router.Router)
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	common.Must(r.Init(&router.Config{
		Rule: []*router.RoutingRule{
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "in_out",
			},
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "udp_bittorrent_blocked",
			},
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "8080_out",
			},
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "9999_out",
			},
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "com_out",
			},
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "127.0.0.1_out",
			},
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "example_out",
			},
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "test"},
				Tag:        "tcp_out",
			},
		},
	}, mocks.NewDNSClient(mockCtl), mocks.NewOutboundManager(mockCtl)))

	lis := bufconn.Listen(1024 * 1024)
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	errCh := make(chan error)

	// Server goroutine
	go func() {
		server := grpc.NewServer()
		RegisterRoutingServiceServer(server, NewRoutingServer(r, c))
		errCh <- server.Serve(lis)
	}()

	// Client goroutine
	go func() {
		defer lis.Close()
		conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
		if err != nil {
			errCh <- err
		}
		defer conn.Close()
		client := NewRoutingServiceClient(conn)

		testAlterRuleCases := []*AlterRoutingRuleRequest{
			{
				Tag: "in_out",
				RoutingRule: &router.RoutingRule{
					InboundTag: []string{"in"},
					TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				},
			},
			{
				Tag: "udp_bittorrent_blocked",
				RoutingRule: &router.RoutingRule{
					Networks:  []net.Network{net.Network_UDP, net.Network_TCP},
					Protocol:  []string{"bittorrent"},
					TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "blocked"},
				},
			},
			{
				Tag: "8080_out",
				RoutingRule: &router.RoutingRule{
					PortList:  &net.PortList{Range: []*net.PortRange{{From: 8080, To: 8080}}},
					TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				},
			},
			{
				Tag: "9999_out",
				RoutingRule: &router.RoutingRule{
					SourcePortList: &net.PortList{Range: []*net.PortRange{{From: 9999, To: 9999}}},
					TargetTag:      &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				},
			},
			{
				Tag: "com_out",
				RoutingRule: &router.RoutingRule{
					Domain:    []*router.Domain{{Type: router.Domain_Domain, Value: "com"}},
					TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				},
			},
			{
				Tag: "127.0.0.1_out",
				RoutingRule: &router.RoutingRule{
					SourceGeoip: []*router.GeoIP{{CountryCode: "private", Cidr: []*router.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}}}},
					TargetTag:   &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				},
			},
			{
				Tag: "example_out",
				RoutingRule: &router.RoutingRule{
					UserEmail: []string{"example@example.com"},
					TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				},
			},
			{
				Tag: "tcp_out",
				RoutingRule: &router.RoutingRule{
					Networks:  []net.Network{net.Network_TCP},
					TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				},
			},
		}

		// Test alter rule
		testAlterRule := func() error {
			for _, tc := range testAlterRuleCases {
				_, err := client.AlterRoutingRule(context.Background(), tc)
				if err != nil {
					return err
				}
			}
			return nil
		}

		testCases := []*RoutingContext{
			{InboundTag: "in", OutboundTag: "out"},
			{TargetIPs: [][]byte{{1, 2, 3, 4}}, TargetPort: 8080, OutboundTag: "out"},
			{TargetDomain: "example.com", TargetPort: 443, OutboundTag: "out"},
			{SourcePort: 9999, TargetPort: 9999, OutboundTag: "out"},
			{Network: net.Network_UDP, Protocol: "bittorrent", OutboundTag: "blocked"},
			{User: "example@example.com", OutboundTag: "out"},
			{SourceIPs: [][]byte{{127, 0, 0, 1}}, Attributes: map[string]string{"attr": "value"}, OutboundTag: "out"},
		}

		// Test simple TestRoute
		testSimple := func() error {
			for _, tc := range testCases {
				route, err := client.TestRoute(context.Background(), &TestRouteRequest{RoutingContext: tc})
				if err != nil {
					return err
				}
				if r := cmp.Diff(route, tc, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
			}
			return nil
		}

		// Test TestRoute with special options
		testOptions := func() error {
			sub, err := c.Subscribe()
			if err != nil {
				return err
			}
			for _, tc := range testCases {
				route, err := client.TestRoute(context.Background(), &TestRouteRequest{
					RoutingContext: tc,
					FieldSelectors: []string{"ip", "port", "domain", "outbound"},
					PublishResult:  true,
				})
				if err != nil {
					return err
				}
				stat := &RoutingContext{ // Only a subset of stats is retrieved
					SourceIPs:         tc.SourceIPs,
					TargetIPs:         tc.TargetIPs,
					SourcePort:        tc.SourcePort,
					TargetPort:        tc.TargetPort,
					TargetDomain:      tc.TargetDomain,
					OutboundGroupTags: tc.OutboundGroupTags,
					OutboundTag:       tc.OutboundTag,
				}
				if r := cmp.Diff(route, stat, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
					t.Error(r)
				}
				select { // Check that routing result has been published to statistics channel
				case msg, received := <-sub:
					if route, ok := msg.(routing.Route); received && ok {
						if r := cmp.Diff(AsProtobufMessage(nil)(route), tc, cmpopts.IgnoreUnexported(RoutingContext{})); r != "" {
							t.Error(r)
						}
					} else {
						t.Error("unexpected failure in receiving published routing result for testcase", tc)
					}
				case <-time.After(100 * time.Millisecond):
					t.Error("unexpected failure in receiving published routing result", tc)
				}
			}
			return nil
		}

		if err := testAlterRule(); err != nil {
			errCh <- err
		}
		if err := testSimple(); err != nil {
			errCh <- err
		}
		if err := testOptions(); err != nil {
			errCh <- err
		}
		errCh <- nil // Client passed all tests successfully
	}()

	// Wait for goroutines to complete
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("Test timeout after 2s")
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceRemoveRoutingRule(t *testing.T) {
	c := stats.NewChannel(&stats.ChannelConfig{
		SubscriberLimit: 1,
		BufferSize:      16,
		Blocking:        true,
	})
	common.Must(c.Start())
	defer c.Close()

	r := new(router.Router)
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	common.Must(r.Init(&router.Config{
		Rule: []*router.RoutingRule{
			{
				InboundTag: []string{"in"},
				TargetTag:  &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				Tag:        "in_out",
			},
			{
				Networks:  []net.Network{net.Network_UDP, net.Network_TCP},
				Protocol:  []string{"bittorrent"},
				Tag:       "udp_bittorrent_blocked",
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "blocked"},
			},
			{
				PortList:  &net.PortList{Range: []*net.PortRange{{From: 8080, To: 8080}}},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				Tag:       "8080_out",
			},
			{
				SourcePortList: &net.PortList{Range: []*net.PortRange{{From: 9999, To: 9999}}},
				TargetTag:      &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				Tag:            "9999_out",
			},
			{
				Domain:    []*router.Domain{{Type: router.Domain_Domain, Value: "com"}},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				Tag:       "com_out",
			},
			{
				SourceGeoip: []*router.GeoIP{{CountryCode: "private", Cidr: []*router.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}}}},
				TargetTag:   &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				Tag:         "127.0.0.1_out",
			},
			{
				UserEmail: []string{"example@example.com"},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				Tag:       "example_out",
			},
			{
				Networks:  []net.Network{net.Network_TCP},
				TargetTag: &router.RoutingRule_OutboundTag{OutboundTag: "out"},
				Tag:       "tcp_out",
			},
		},
	}, mocks.NewDNSClient(mockCtl), mocks.NewOutboundManager(mockCtl)))

	lis := bufconn.Listen(1024 * 1024)
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	errCh := make(chan error)

	// Server goroutine
	go func() {
		server := grpc.NewServer()
		RegisterRoutingServiceServer(server, NewRoutingServer(r, c))
		errCh <- server.Serve(lis)
	}()

	// Client goroutine
	go func() {
		defer lis.Close()
		conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
		if err != nil {
			errCh <- err
		}
		defer conn.Close()
		client := NewRoutingServiceClient(conn)

		testRemoveRuleCases := []string{
			"in_out",
			"udp_bittorrent_blocked",
			"8080_out",
			"9999_out",
			"com_out",
			"127.0.0.1_out",
			"example_out",
			"tcp_out",
		}

		// Test alter rule
		testRemoveRule := func() error {
			for _, tc := range testRemoveRuleCases {
				_, err := client.RemoveRoutingRule(context.Background(), &RemoveRoutingRuleRequest{Tag: tc})
				if err != nil {
					return err
				}
			}
			return nil
		}

		testCases := []*RoutingContext{
			{InboundTag: "in", OutboundTag: "out"},
			{TargetIPs: [][]byte{{1, 2, 3, 4}}, TargetPort: 8080, OutboundTag: "out"},
			{TargetDomain: "example.com", TargetPort: 443, OutboundTag: "out"},
			{SourcePort: 9999, TargetPort: 9999, OutboundTag: "out"},
			{Network: net.Network_UDP, Protocol: "bittorrent", OutboundTag: "blocked"},
			{User: "example@example.com", OutboundTag: "out"},
			{SourceIPs: [][]byte{{127, 0, 0, 1}}, Attributes: map[string]string{"attr": "value"}, OutboundTag: "out"},
		}

		// Test simple TestRoute
		testSimple := func() error {
			for _, tc := range testCases {
				route, err := client.TestRoute(context.Background(), &TestRouteRequest{RoutingContext: tc})
				if err == nil {
					return errors.New(fmt.Sprintf("Delete route failed, remaining route:[%s]", route.Tag))
				}
			}
			return nil
		}

		if err := testRemoveRule(); err != nil {
			errCh <- err
		}
		if err := testSimple(); err != nil {
			errCh <- err
		}
		errCh <- nil // Client passed all tests successfully
	}()

	// Wait for goroutines to complete
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("Test timeout after 2s")
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	}
}


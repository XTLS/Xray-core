package splithttp_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

type fakeRoundTripper struct{}

func TestMaxConnections(t *testing.T) {
	config := Multiplexing{
		MaxConnections: &RandRangeConfig{From: 4, To: 4},
	}

	mux := NewMuxManager(config, func() interface{} {
		return &fakeRoundTripper{}
	})

	clients := make(map[interface{}]struct{})
	for i := 0; i < 8; i++ {
		clients[mux.GetResource(context.Background())] = struct{}{}
	}

	if len(clients) != 4 {
		t.Error("did not get 4 distinct clients, got ", len(clients))
	}
}

func TestCMaxReuseTimes(t *testing.T) {
	config := Multiplexing{
		CMaxReuseTimes: &RandRangeConfig{From: 2, To: 2},
	}

	mux := NewMuxManager(config, func() interface{} {
		return &fakeRoundTripper{}
	})

	clients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		clients[mux.GetResource(context.Background())] = struct{}{}
	}

	if len(clients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(clients))
	}
}

func TestMaxConcurrency(t *testing.T) {
	config := Multiplexing{
		MaxConcurrency: &RandRangeConfig{From: 2, To: 2},
	}

	mux := NewMuxManager(config, func() interface{} {
		return &fakeRoundTripper{}
	})

	clients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		client := mux.GetResource(context.Background())
		client.OpenRequests.Add(1)
		clients[client] = struct{}{}
	}

	if len(clients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(clients))
	}
}

func TestDefault(t *testing.T) {
	config := Multiplexing{}

	mux := NewMuxManager(config, func() interface{} {
		return &fakeRoundTripper{}
	})

	clients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		client := mux.GetResource(context.Background())
		client.OpenRequests.Add(1)
		clients[client] = struct{}{}
	}

	if len(clients) != 1 {
		t.Error("did not get 1 distinct clients, got ", len(clients))
	}
}

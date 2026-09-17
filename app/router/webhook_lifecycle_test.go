package router

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

type webhookTestTransport func(*http.Request) (*http.Response, error)

func (f webhookTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type blockingWebhookContext struct {
	routing.Context
	started chan struct{}
	release chan struct{}
}

func (c *blockingWebhookContext) GetInboundTag() string {
	close(c.started)
	<-c.release
	return ""
}

func countWebhookPosts(h *WebhookNotifier, posts *atomic.Int32) {
	h.client.Transport = webhookTestTransport(func(*http.Request) (*http.Response, error) {
		posts.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
}

func newTestWebhookNotifier(t *testing.T, posts *atomic.Int32) *WebhookNotifier {
	t.Helper()
	h, err := NewWebhookNotifier(&WebhookConfig{Url: "http://webhook.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	countWebhookPosts(h, posts)
	return h
}

func TestWebhookCloseWaitsForAcceptedFire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var posts atomic.Int32
		h := newTestWebhookNotifier(t, &posts)
		ctx := &blockingWebhookContext{
			Context: &routing_session.Context{},
			started: make(chan struct{}),
			release: make(chan struct{}),
		}
		fired := make(chan struct{})
		go func() {
			h.Fire(ctx, "outbound")
			close(fired)
		}()
		<-ctx.started

		closed := make(chan struct{})
		go func() {
			h.Close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
			close(ctx.release)
			<-fired
			t.Fatal("Close returned before an accepted Fire completed")
		default:
		}

		close(ctx.release)
		<-fired
		<-closed
		if got := posts.Load(); got != 1 {
			t.Fatalf("Close did not drain the accepted webhook: got %d posts", got)
		}

		h.Fire(&routing_session.Context{}, "after-close")
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if got := posts.Load(); got != 1 {
			t.Fatalf("Fire posted after Close: got %d posts", got)
		}
	})
}

func TestWebhookConcurrentFireAndClose(t *testing.T) {
	for range 200 {
		var posts atomic.Int32
		h := newTestWebhookNotifier(t, &posts)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				<-start
				h.Fire(&routing_session.Context{}, "outbound")
			})
		}
		for range 2 {
			wg.Go(func() {
				<-start
				h.Close()
			})
		}
		close(start)
		wg.Wait()
	}
}

func TestWebhookCloseAfterDuplicateFire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, err := NewWebhookNotifier(&WebhookConfig{
			Url:           "http://webhook.invalid",
			Deduplication: 60,
		})
		if err != nil {
			t.Fatal(err)
		}
		var posts atomic.Int32
		countWebhookPosts(h, &posts)
		ctx := &routing_session.Context{Inbound: &session.Inbound{
			User: &protocol.MemoryUser{Email: "user@example.invalid"},
		}}

		h.Fire(ctx, "outbound")
		h.Fire(ctx, "outbound")
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if got := posts.Load(); got != 1 {
			t.Fatalf("duplicate Fire was not suppressed: got %d posts", got)
		}
	})
}

func TestRouterUpdateWaitsForRetiredWebhook(t *testing.T) {
	for _, test := range []struct {
		name   string
		update func(*Router) error
	}{
		{"replace", func(r *Router) error { return r.ReloadRules(&Config{}, false) }},
		{"remove", func(r *Router) error { return r.RemoveRule("old") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := new(Router)
				if err := r.Init(context.Background(), &Config{Rule: []*RoutingRule{{
					RuleTag:   "old",
					TargetTag: &RoutingRule_Tag{Tag: "outbound"},
					Networks:  []net.Network{net.Network_TCP},
					Webhook:   &WebhookConfig{Url: "http://webhook.invalid"},
				}}}, nil, nil, nil); err != nil {
					t.Fatal(err)
				}
				h := (*r.rules.Load())[0].Webhook
				var posts atomic.Int32
				countWebhookPosts(h, &posts)
				ctx := &blockingWebhookContext{
					Context: &routing_session.Context{},
					started: make(chan struct{}),
					release: make(chan struct{}),
				}
				go h.Fire(ctx, "outbound")
				<-ctx.started

				updated := make(chan error, 1)
				go func() { updated <- test.update(r) }()
				<-h.done // The replacement is published before retirement drains Fire.
				if len(r.ListRule()) != 0 {
					t.Error("update did not publish its replacement before retiring the webhook")
				}

				synctest.Wait()
				updateReturned := false
				select {
				case <-updated:
					updateReturned = true
					t.Error("router update returned before the retired webhook finished")
				default:
				}

				close(ctx.release)
				if !updateReturned {
					if err := <-updated; err != nil {
						t.Fatal(err)
					}
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if got := posts.Load(); got != 1 {
					t.Fatalf("retired webhook was not drained: got %d posts", got)
				}
			})
		})
	}
}

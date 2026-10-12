package finalmask

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDialContextPreservesParentAndCancelsRequest(t *testing.T) {
	type key struct{}
	parent := context.WithValue(context.Background(), key{}, "outbound")
	request, cancelRequest := context.WithCancel(context.Background())
	ctx, cleanup := contextForDial(parent, request)
	defer cleanup()
	if ctx.Value(key{}) != "outbound" { t.Fatal("outbound context value was lost") }
	cancelRequest()
	select { case <-ctx.Done(): case <-time.After(time.Second): t.Fatal("request cancellation did not cancel dial") }
	if !errors.Is(ctx.Err(), context.Canceled) { t.Fatal(ctx.Err()) }
}

func TestDialContextHonorsBothDeadlines(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), time.Minute)
	defer cancelParent()
	request, cancelRequest := context.WithTimeout(context.Background(), time.Second)
	defer cancelRequest()
	ctx, cleanup := contextForDial(parent, request)
	defer cleanup()
	got, _ := ctx.Deadline()
	want, _ := request.Deadline()
	if !got.Equal(want) { t.Fatalf("dial deadline %v, want %v", got, want) }
	cancelParent()
	select { case <-ctx.Done(): case <-time.After(time.Second): t.Fatal("parent cancellation did not cancel dial") }
}

package stats

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features"
)

// Counter is the interface for stats counters.
//
// xray:api:stable
type Counter interface {
	// Value is the current value of the counter.
	Value() int64
	// Set sets a new value to the counter, and returns the previous one.
	Set(int64) int64
	// Add adds a value to the current counter value, and returns the previous value.
	Add(int64) int64
}

// OnlineMap is the interface for tracking online IP addresses.
//
// xray:api:stable
type OnlineMap interface {
	// Count returns the number of unique online IPs.
	Count() int
	// AddIP increments the reference count for the given IP.
	AddIP(string)
	// RemoveIP decrements the reference count for the given IP. Deletes at zero.
	RemoveIP(string)
	// ForEach calls fn for each online IP with its last-seen Unix timestamp.
	// If fn returns false, iteration stops.
	// The callback must not call AddIP/RemoveIP on the same OnlineMap (would deadlock).
	ForEach(func(string, int64) bool)
}

// Channel is the interface for stats channel.
//
// xray:api:stable
type Channel interface {
	// Runnable implies that Channel is a runnable unit.
	common.Runnable
	// Publish broadcasts a message through the channel with a controlling context.
	Publish(context.Context, interface{})
	// Subscribers returns all subscribers.
	Subscribers() []chan interface{}
	// Subscribe registers for listening to channel stream and returns a new listener channel.
	Subscribe() (chan interface{}, error)
	// Unsubscribe unregisters a listener channel from current Channel object.
	Unsubscribe(chan interface{}) error
}

// SubscribeRunnableChannel subscribes the channel and starts it if there is first subscriber coming.
func SubscribeRunnableChannel(c Channel) (chan interface{}, error) {
	if len(c.Subscribers()) == 0 {
		if err := c.Start(); err != nil {
			return nil, err
		}
	}
	return c.Subscribe()
}

// UnsubscribeClosableChannel unsubscribes the channel and close it if there is no more subscriber.
func UnsubscribeClosableChannel(c Channel, sub chan interface{}) error {
	if err := c.Unsubscribe(sub); err != nil {
		return err
	}
	if len(c.Subscribers()) == 0 {
		return c.Close()
	}
	return nil
}

// Manager is the interface for stats manager.
//
// xray:api:stable
type Manager interface {
	features.Feature

	// RegisterCounter registers a new counter to the manager. The identifier string must not be empty, and unique among other counters.
	RegisterCounter(string) (Counter, error)
	// UnregisterCounter unregisters a counter from the manager by its identifier.
	UnregisterCounter(string) error
	// GetCounter returns a counter by its identifier.
	GetCounter(string) Counter
	// VisitCounters calls visitor on all managed counters.
	// The visitor runs under a read lock; it must not call RegisterCounter or UnregisterCounter (would deadlock).
	VisitCounters(func(string, Counter) bool)

	// RegisterOnlineMap registers a new OnlineMap to the manager. The identifier string must not be empty, and unique among other OnlineMaps.
	RegisterOnlineMap(string) (OnlineMap, error)
	// UnregisterOnlineMap unregisters an OnlineMap from the manager by its identifier.
	UnregisterOnlineMap(string) error
	// GetOnlineMap returns an OnlineMap by its identifier.
	GetOnlineMap(string) OnlineMap
	// VisitOnlineMaps calls visitor on all managed online maps.
	// The visitor runs under a read lock; it must not call RegisterOnlineMap or UnregisterOnlineMap (would deadlock).
	VisitOnlineMaps(func(string, OnlineMap) bool)

	// RegisterChannel registers a new channel to the manager. The identifier string must not be empty, and unique among other channels.
	RegisterChannel(string) (Channel, error)
	// UnregisterChannel unregisters a channel from the manager by its identifier.
	UnregisterChannel(string) error
	// GetChannel returns a channel by its identifier.
	GetChannel(string) Channel

	// GetAllOnlineUsers returns all online users from all OnlineMaps.
	GetAllOnlineUsers() []string
}

// GetOrRegisterCounter tries to get the StatCounter first. If not exist, it then tries to create a new counter.
func GetOrRegisterCounter(m Manager, name string) (Counter, error) {
	counter := m.GetCounter(name)
	if counter != nil {
		return counter, nil
	}

	return m.RegisterCounter(name)
}

// GetOrRegisterOnlineMap tries to get the OnlineMap first. If not exist, it then tries to create a new OnlineMap.
func GetOrRegisterOnlineMap(m Manager, name string) (OnlineMap, error) {
	onlineMap := m.GetOnlineMap(name)
	if onlineMap != nil {
		return onlineMap, nil
	}

	return m.RegisterOnlineMap(name)
}

// GetOrRegisterChannel tries to get the StatChannel first. If not exist, it then tries to create a new channel.
func GetOrRegisterChannel(m Manager, name string) (Channel, error) {
	channel := m.GetChannel(name)
	if channel != nil {
		return channel, nil
	}

	return m.RegisterChannel(name)
}

// ManagerType returns the type of Manager interface. Can be used to implement common.HasType.
//
// xray:api:stable
func ManagerType() interface{} {
	return (*Manager)(nil)
}

// NoopManager is an implementation of Manager, which doesn't have actual functionality.
type NoopManager struct{}

// Type implements common.HasType.
func (NoopManager) Type() interface{} {
	return ManagerType()
}

// RegisterCounter implements Manager.
func (NoopManager) RegisterCounter(string) (Counter, error) {
	return nil, errors.New("not implemented")
}

// UnregisterCounter implements Manager.
func (NoopManager) UnregisterCounter(string) error {
	return nil
}

// GetCounter implements Manager.
func (NoopManager) GetCounter(string) Counter {
	return nil
}

// VisitCounters implements Manager.
func (NoopManager) VisitCounters(func(string, Counter) bool) {}

// RegisterOnlineMap implements Manager.
func (NoopManager) RegisterOnlineMap(string) (OnlineMap, error) {
	return nil, errors.New("not implemented")
}

// UnregisterOnlineMap implements Manager.
func (NoopManager) UnregisterOnlineMap(string) error {
	return nil
}

// GetOnlineMap implements Manager.
func (NoopManager) GetOnlineMap(string) OnlineMap {
	return nil
}

// VisitOnlineMaps implements Manager.
func (NoopManager) VisitOnlineMaps(func(string, OnlineMap) bool) {}

// RegisterChannel implements Manager.
func (NoopManager) RegisterChannel(string) (Channel, error) {
	return nil, errors.New("not implemented")
}

// UnregisterChannel implements Manager.
func (NoopManager) UnregisterChannel(string) error {
	return nil
}

// GetChannel implements Manager.
func (NoopManager) GetChannel(string) Channel {
	return nil
}

// GetAllOnlineUsers implements Manager.
func (NoopManager) GetAllOnlineUsers() []string {
	return nil
}

// Start implements common.Runnable.
func (NoopManager) Start() error { return nil }

// Close implements common.Closable.
func (NoopManager) Close() error { return nil }

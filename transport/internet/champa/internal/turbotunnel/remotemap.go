package turbotunnel

import (
	"container/heap"
	"net"
	"sync"
	"time"
)

// remoteRecord is a record of a recently seen remote peer, with the time it was
// last seen and queues of outgoing packets.
type remoteRecord struct {
	Addr      net.Addr
	LastSeen  time.Time
	SendQueue chan []byte
	Stash     chan []byte
}

// RemoteMap manages a mapping of live remote peers, keyed by address, to their
// respective send queues. Each peer has two queues: a primary send queue, and a
// "stash". The primary send queue is returned by the SendQueue method. The
// stash is an auxiliary one-element queue accessed using the Stash and Unstash
// methods. The stash is meant for use by callers that need to "unread" a packet
// that's already been removed from the primary send queue.
//
// RemoteMap's functions are safe to call from multiple goroutines.
type RemoteMap struct {
	// We use an inner structure to avoid exposing public heap.Interface
	// functions to users of remoteMap.
	inner remoteMapInner
	// Synchronizes access to inner.
	lock sync.Mutex
}

// NewRemoteMap creates a RemoteMap that expires peers after a timeout.
//
// If the timeout is 0, peers never expire.
//
// The timeout does not have to be kept in sync with smux's idle timeout. If a
// peer is removed from the map while the smux session is still live, the worst
// that can happen is a loss of whatever packets were in the send queue at the
// time. If smux later decides to send more packets to the same peer, we'll
// instantiate a new send queue, and if the peer is ever seen again with a
// matching address, we'll deliver them.
func NewRemoteMap(timeout time.Duration) *RemoteMap {
	m := &RemoteMap{
		inner: remoteMapInner{
			byAge:  make([]*remoteRecord, 0),
			byAddr: make(map[net.Addr]int),
		},
	}
	if timeout > 0 {
		go func() {
			for {
				time.Sleep(timeout / 2)
				now := time.Now()
				m.lock.Lock()
				m.inner.removeExpired(now, timeout)
				m.lock.Unlock()
			}
		}()
	}
	return m
}

// SendQueue returns the send queue corresponding to addr, creating it if
// necessary.
func (m *RemoteMap) SendQueue(addr net.Addr) chan []byte {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.inner.Lookup(addr, time.Now()).SendQueue
}

// Stash places p in the stash corresponding to addr, if the stash is not
// already occupied. Returns true if the p was placed in the stash, false
// otherwise.
func (m *RemoteMap) Stash(addr net.Addr, p []byte) bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	select {
	case m.inner.Lookup(addr, time.Now()).Stash <- p:
		return true
	default:
		return false
	}
}

// Unstash returns the channel that reads from the stash for addr.
func (m *RemoteMap) Unstash(addr net.Addr) <-chan []byte {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.inner.Lookup(addr, time.Now()).Stash
}

// remoteMapInner is the inner type of RemoteMap, implementing heap.Interface.
// byAge is the backing store, a heap ordered by LastSeen time, to facilitate
// expiring old records. byAddr is a map from addresses to heap indices, to
// allow looking up by address. Unlike RemoteMap, remoteMapInner requires
// external synchonization.
type remoteMapInner struct {
	byAge  []*remoteRecord
	byAddr map[net.Addr]int
}

// removeExpired removes all records whose LastSeen timestamp is more than
// timeout in the past.
func (inner *remoteMapInner) removeExpired(now time.Time, timeout time.Duration) {
	for len(inner.byAge) > 0 && now.Sub(inner.byAge[0].LastSeen) >= timeout {
		record := heap.Pop(inner).(*remoteRecord)
		close(record.SendQueue)
	}
}

// Lookup finds the existing record corresponding to addr, or creates a new
// one if none exists yet. It updates the record's LastSeen time and returns the
// record.
func (inner *remoteMapInner) Lookup(addr net.Addr, now time.Time) *remoteRecord {
	var record *remoteRecord
	i, ok := inner.byAddr[addr]
	if ok {
		// Found one, update its LastSeen.
		record = inner.byAge[i]
		record.LastSeen = now
		heap.Fix(inner, i)
	} else {
		// Not found, create a new one.
		record = &remoteRecord{
			Addr:      addr,
			LastSeen:  now,
			SendQueue: make(chan []byte, queueSize),
			Stash:     make(chan []byte, 1),
		}
		heap.Push(inner, record)
	}
	return record
}

// heap.Interface for remoteMapInner.

func (inner *remoteMapInner) Len() int {
	if len(inner.byAge) != len(inner.byAddr) {
		panic("inconsistent remoteMap")
	}
	return len(inner.byAge)
}

func (inner *remoteMapInner) Less(i, j int) bool {
	return inner.byAge[i].LastSeen.Before(inner.byAge[j].LastSeen)
}

func (inner *remoteMapInner) Swap(i, j int) {
	inner.byAge[i], inner.byAge[j] = inner.byAge[j], inner.byAge[i]
	inner.byAddr[inner.byAge[i].Addr] = i
	inner.byAddr[inner.byAge[j].Addr] = j
}

func (inner *remoteMapInner) Push(x interface{}) {
	record := x.(*remoteRecord)
	if _, ok := inner.byAddr[record.Addr]; ok {
		panic("duplicate address in remoteMap")
	}
	// Insert into byAddr map.
	inner.byAddr[record.Addr] = len(inner.byAge)
	// Insert into byAge slice.
	inner.byAge = append(inner.byAge, record)
}

func (inner *remoteMapInner) Pop() interface{} {
	n := len(inner.byAddr)
	// Remove from byAge slice.
	record := inner.byAge[n-1]
	inner.byAge[n-1] = nil
	inner.byAge = inner.byAge[:n-1]
	// Remove from byAddr map.
	delete(inner.byAddr, record.Addr)
	return record
}

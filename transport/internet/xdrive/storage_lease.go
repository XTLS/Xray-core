package xdrive

import (
	"context"
	"sync"
)

type storageOwner struct {
	root      Storage
	key       string
	refs      int
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

type storageLease struct {
	owner    *storageOwner
	backend  Storage
	session  bool
	mu       sync.Mutex
	closed   bool
	closeErr error
}

type (
	leasedStorage      struct{ *storageLease }
	leasedDriveStorage struct {
		*driveStorage
		lease *storageLease
	}
)

type leasedTemplateStorage struct {
	*templateStorage
	lease *storageLease
}
type leasedS3Storage struct {
	*s3Storage
	lease *storageLease
}
type leasedSlotStorage struct {
	*leasedStorage
	slotStore
}

func wrapStorageLease(owner *storageOwner, backend Storage, session bool) Storage {
	lease := &storageLease{owner: owner, backend: backend, session: session}
	switch s := backend.(type) {
	case *driveStorage:
		return &leasedDriveStorage{driveStorage: s, lease: lease}
	case *templateStorage:
		return &leasedTemplateStorage{templateStorage: s, lease: lease}
	case *s3Storage:
		return &leasedS3Storage{s3Storage: s, lease: lease}
	default:
		storage := &leasedStorage{storageLease: lease}
		if slots, ok := backend.(slotStore); ok {
			return &leasedSlotStorage{leasedStorage: storage, slotStore: slots}
		}
		return storage
	}
}

func ownedStorage(storage Storage) Storage {
	return wrapStorageLease(&storageOwner{root: storage, refs: 1}, storage, false)
}

func (s *storageLease) storageLeaseState() *storageLease          { return s }
func (s *leasedDriveStorage) storageLeaseState() *storageLease    { return s.lease }
func (s *leasedTemplateStorage) storageLeaseState() *storageLease { return s.lease }
func (s *leasedS3Storage) storageLeaseState() *storageLease       { return s.lease }

func (s *leasedStorage) Put(ctx context.Context, name string, data []byte) error {
	return s.backend.Put(ctx, name, data)
}

func (s *leasedStorage) Get(ctx context.Context, name string) ([]byte, error) {
	return s.backend.Get(ctx, name)
}

func (s *leasedStorage) Delete(ctx context.Context, name string) error {
	return s.backend.Delete(ctx, name)
}

func (s *leasedStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	return s.backend.List(ctx, prefix)
}
func (s *leasedDriveStorage) Close() error    { return s.lease.Close() }
func (s *leasedTemplateStorage) Close() error { return s.lease.Close() }
func (s *leasedS3Storage) Close() error       { return s.lease.Close() }

func (s *storageLease) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.session && s.backend != s.owner.root {
		s.closeErr = s.backend.Close()
	}
	sharedMu.Lock()
	s.owner.refs--
	final := s.owner.refs == 0 && !s.owner.closed
	if final {
		s.owner.closed = true
		if s.owner.key != "" && shared[s.owner.key] == s.owner {
			delete(shared, s.owner.key)
		}
	}
	sharedMu.Unlock()
	if final {
		if err := s.owner.close(); s.closeErr == nil {
			s.closeErr = err
		}
	}
	return s.closeErr
}

func (o *storageOwner) close() error {
	o.closeOnce.Do(func() { o.closeErr = closeStorageRoot(o.root) })
	return o.closeErr
}

func acquireSessionStorage(storage Storage) (Storage, error) {
	if s, ok := storage.(interface{ storageLeaseState() *storageLease }); ok {
		lease := s.storageLeaseState()
		lease.mu.Lock()
		defer lease.mu.Unlock()
		sharedMu.Lock()
		if lease.closed || lease.owner.closed {
			sharedMu.Unlock()
			return nil, errSessionClosed
		}
		lease.owner.refs++
		sharedMu.Unlock()
		return wrapStorageLease(lease.owner, rawSessionStorage(lease.owner.root), true), nil
	}
	return rawSessionStorage(storage), nil
}

// Dial and spare construction transfer their acquisition to a session. A
// listener instead keeps its acquisition and clones one lease per child.
func transferSessionStorage(storage Storage) (Storage, error) {
	session, err := acquireSessionStorage(storage)
	if err != nil {
		storage.Close()
		return nil, err
	}
	if _, ok := storage.(interface{ storageLeaseState() *storageLease }); ok {
		storage.Close()
	}
	return session, nil
}

func holdStorageSession(storage Storage, session string) (func(), error) {
	if s, ok := storage.(interface{ holdSession(string) (func(), error) }); ok {
		return s.holdSession(session)
	}
	return func() {}, nil
}

func closeStorageRoot(storage Storage) error {
	switch s := storage.(type) {
	case *templateStorage:
		s.closeTokenWorkers()
		closeStoragePool(s.conns)
		if s.client != nil {
			s.client.CloseIdleConnections()
		}
		if s.tokenClient != nil {
			s.tokenClient.CloseIdleConnections()
		}
	case *s3Storage:
		closeStoragePool(s.conns)
		if s.client != nil {
			s.client.CloseIdleConnections()
		}
	}
	return storage.Close()
}

func closeStoragePool(pool *connPool) {
	if pool != nil {
		pool.Close()
	}
}

package xdrive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

var errNotFound = errors.New("XDRIVE: object not found")

type Entry struct {
	Name   string
	Inline []byte
}

type Storage interface {
	Put(ctx context.Context, name string, data []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, prefix string) ([]Entry, error)
	Close() error
}

func newStorage(config *Config) (Storage, error) {
	switch config.Service {
	case "local":
		return newLocalStorage(config.RemoteFolder)
	case "Google Drive":
		return sharedStorage(config, func() (Storage, error) { return newDriveStorage(config) })
	default:
		return nil, errors.New("XDRIVE: unsupported service: ", config.Service)
	}
}

var (
	sharedMu sync.Mutex
	shared   = make(map[string]Storage)
)

func shareKey(config *Config) string {
	sum := sha256.Sum256([]byte(strings.Join(append(
		[]string{config.Service, config.RemoteFolder}, config.Secrets...), "\x00")))
	return hex.EncodeToString(sum[:])
}

func resetSharedStorage() {
	sharedMu.Lock()
	shared = make(map[string]Storage)
	sharedMu.Unlock()
}

func sharedStorage(config *Config, build func() (Storage, error)) (Storage, error) {
	key := shareKey(config)

	sharedMu.Lock()
	defer sharedMu.Unlock()

	if storage, ok := shared[key]; ok {
		return storage, nil
	}
	storage, err := build()
	if err != nil {
		return nil, err
	}
	shared[key] = storage
	return storage, nil
}

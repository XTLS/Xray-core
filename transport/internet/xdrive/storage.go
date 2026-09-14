package xdrive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

var errNotFound = errors.New("object not found")

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

func newStorage(streamSettings *internet.MemoryStreamConfig) (Storage, error) {
	config, err := streamConfig(streamSettings)
	if err != nil {
		return nil, err
	}

	switch config.Service {
	case "local":
		return newLocalStorage(config.RemoteFolder)
	case "Google Drive":
		return sharedStorage(streamSettings, config, func() (Storage, error) {
			return newDriveStorage(streamSettings, config)
		})
	default:
		return nil, errors.New("unsupported service: ", config.Service)
	}
}

var (
	sharedMu sync.Mutex
	shared   = make(map[string]Storage)
)

func shareKey(streamSettings *internet.MemoryStreamConfig, config *Config) string {
	parts := []string{config.Service, config.RemoteFolder}
	parts = append(parts, config.Secrets...)
	if streamSettings != nil {
		parts = append(parts, streamSettings.SecurityType)
		if streamSettings.Destination != nil {
			parts = append(parts, streamSettings.Destination.NetAddr())
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func resetSharedStorage() {
	sharedMu.Lock()
	shared = make(map[string]Storage)
	sharedMu.Unlock()
}

func sharedStorage(streamSettings *internet.MemoryStreamConfig, config *Config, build func() (Storage, error)) (Storage, error) {
	key := shareKey(streamSettings, config)

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

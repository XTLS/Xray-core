package xdrive

import (
	"context"

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
		return nil, errors.New(`service "Google Drive" is not implemented yet`)
	default:
		return nil, errors.New("unsupported service: ", config.Service)
	}
}

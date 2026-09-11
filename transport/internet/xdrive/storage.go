package xdrive

import (
	"context"

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
		return nil, errors.New(`XDRIVE: service "Google Drive" is not implemented yet`)
	default:
		return nil, errors.New("XDRIVE: unsupported service: ", config.Service)
	}
}

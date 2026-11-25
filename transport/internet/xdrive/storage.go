package xdrive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var errNotFound = errors.New("object not found")

type Entry struct {
	Name    string
	Inline  []byte
	created time.Time // optional backend-supplied creation time on the local clock
}

// Config.Secrets for clients need only create/update/read/list permissions;
// only server credentials need delete permission.
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
		storage, err := newLocalStorage(config.RemoteFolder)
		if err != nil {
			return nil, err
		}
		return ownedStorage(storage), nil
	case "google-drive", "Google Drive":
		return sharedStorage(streamSettings, config, func() (Storage, error) {
			return newDriveStorage(streamSettings, config)
		})
	case "template":
		return sharedStorage(streamSettings, config, func() (Storage, error) {
			return newTemplateStorage(streamSettings, config)
		})
	case "s3":
		return sharedStorage(streamSettings, config, func() (Storage, error) {
			return newS3Storage(streamSettings, config)
		})
	default:
		return nil, errors.New("unsupported service: ", config.Service)
	}
}

func rawSessionStorage(storage Storage) Storage {
	switch s := storage.(type) {
	case *driveStorage:
		return s.session()
	case *templateStorage:
		return s.session()
	case *s3Storage:
		return s.session()
	}
	return storage
}

var (
	sharedMu sync.Mutex
	shared   = make(map[string]*storageOwner)
)

func shareKey(streamSettings *internet.MemoryStreamConfig, config *Config) string {
	// Encode only configuration, not protobuf runtime state or transport caches.
	// JSON provides field/element boundaries (unlike NUL-joined strings), with
	// deterministic map ordering. These concrete config types contain no funcs.
	profile := struct {
		Service, Folder, Template, SecurityType, Destination string
		Secrets                                              []string
		S3                                                   *S3Config
		TLS                                                  *tls.Config
		Socket                                               *internet.SocketConfig
		QUIC                                                 *internet.QuicParams
		XMUX                                                 *splithttp.XmuxConfig
	}{
		Service: config.Service, Folder: config.RemoteFolder, Secrets: config.Secrets,
		Template: config.Template, XMUX: config.Xmux,
	}
	if config.S3 != nil {
		profile.S3 = &S3Config{
			Endpoint: config.S3.Endpoint, Region: s3Region(config.S3.Region),
			Bucket: config.S3.Bucket, PathStyle: config.S3.PathStyle,
		}
	}
	if streamSettings != nil {
		profile.SecurityType = streamSettings.SecurityType
		profile.TLS = tls.ConfigFromStreamSettings(streamSettings)
		profile.Socket, profile.QUIC = streamSettings.SocketSettings, streamSettings.QuicParams
		if streamSettings.Destination != nil {
			profile.Destination = streamSettings.Destination.String()
		}
	}
	h := sha256.New()
	common.Must(json.NewEncoder(h).Encode(profile))
	return hex.EncodeToString(h.Sum(nil))
}

func sharedStorage(streamSettings *internet.MemoryStreamConfig, config *Config, build func() (Storage, error)) (Storage, error) {
	// Opaque masks have no immutable configuration identity. Isolate their
	// owners rather than accidentally routing one profile through another.
	if streamSettings != nil && streamSettings.FinalMask != nil {
		storage, err := build()
		if err != nil {
			return nil, err
		}
		return ownedStorage(storage), nil
	}
	key := shareKey(streamSettings, config)

	sharedMu.Lock()
	defer sharedMu.Unlock()

	if owner, ok := shared[key]; ok && !owner.closed {
		owner.refs++
		return wrapStorageLease(owner, owner.root, false), nil
	}
	storage, err := build()
	if err != nil {
		return nil, err
	}
	owner := &storageOwner{root: storage, key: key, refs: 1}
	shared[key] = owner
	return wrapStorageLease(owner, storage, false), nil
}

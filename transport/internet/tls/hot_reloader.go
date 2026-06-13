package tls

import (
	"context"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/utils"
)

var certsCache = utils.NewWeakCacheMap[uintptr, Certificate]()

var startHotReload sync.Once

func setupHotReload(entry *Certificate) {
	startHotReload.Do(func() {
		go handleHotReload()
	})
	// ensure the cache before use
	entry.getX509KeyPair()
	if entry.OneTimeLoading {
		return
	}
	uptr := uintptr(unsafe.Pointer(entry))
	if _, ok := certsCache.Load(uptr); !ok {
		certsCache.Store(uptr, entry)
	}
}

func handleHotReload() {
	// should be enough?
	t := time.NewTicker(600 * time.Second)
	for {
		certsCache.Range(updateCert)
		<-t.C
	}
}

func updateCert(_ uintptr, entry *Certificate) bool {
	reloadInterval := int64(entry.OcspStapling)
	if reloadInterval <= 0 {
		reloadInterval = 3600
	}
	if entry.LastReload+reloadInterval >= time.Now().Unix() {
		return true
	} else {
		entry.LastReload = time.Now().Unix()
	}
	if entry.CertificatePath != "" && entry.KeyPath != "" {
		newCert, err := filesystem.ReadCert(entry.CertificatePath)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to parse certificate")
			return true
		}
		newKey, err := filesystem.ReadCert(entry.KeyPath)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to parse key")
			return true
		}
		if string(newCert) != string(entry.Certificate) || string(newKey) != string(entry.Key) {
			entry.Certificate = newCert
			entry.Key = newKey
		}
	}
	entry.parseX509KeyPair()
	if entry.OcspStapling > 0 {
		keyPair := entry.getX509KeyPair()
		if keyPair == nil {
			return true
		}
		if newOCSPData, err := ocsp.GetOCSPForCert(keyPair.Certificate); err != nil {
			errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
		} else if !slices.Equal(newOCSPData, entry.OcspData) {
			entry.OcspData = newOCSPData
		}
		entry.parseX509KeyPair()
	}
	return true
}

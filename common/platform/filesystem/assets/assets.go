//go:build ios || darwin

package assets

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
)

type GeoMeta struct {
	Code   string
	Start  int64
	Length int64
}

type MMapFile struct {
	mu   sync.RWMutex
	path string
	data []byte
	size int

	GeoMeta []GeoMeta
}

var GeoSite *MMapFile
var GeoIP *MMapFile

func ReadGeoIP(file string) ([]byte, error) {
	if GeoIP == nil {
		GeoIP = &MMapFile{GeoMeta: []GeoMeta{}}
		if err := GeoIP.Open(platform.GetAssetLocation(file)); err != nil {
			return nil, err
		}
	}
	return GeoIP.Bytes(), nil
}

func ReadGeoSite(file string) ([]byte, error) {
	if GeoSite == nil {
		GeoSite = &MMapFile{GeoMeta: []GeoMeta{}}
		if err := GeoSite.Open(platform.GetAssetLocation(file)); err != nil {
			return nil, err
		}
	}

	return GeoSite.Bytes(), nil
}

// Open maps the file readonly
func (m *MMapFile) Open(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}

	size64 := st.Size()
	if size64 <= 0 {
		m.mu.Lock()
		_ = m.unmapLocked()
		m.path, m.data, m.size = path, nil, 0
		m.mu.Unlock()
		return nil
	}
	if size64 > int64(^uint(0)>>1) {
		return fmt.Errorf("file too large: %d", size64)
	}
	size := int(size64)

	b, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return err
	}

	_ = unix.Madvise(b, unix.MADV_RANDOM)

	m.mu.Lock()
	_ = m.unmapLocked()
	m.path = path
	m.data = b
	m.size = size
	m.mu.Unlock()

	m.buildGeoMetaList()

	return nil
}

func (m *MMapFile) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unmapLocked()
}

func (m *MMapFile) Bytes() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.data
}

func (m *MMapFile) Slice(start, end int64) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if start < 0 || end < start || int(end) > len(m.data) {
		return nil
	}
	return m.data[start:end]
}

func (m *MMapFile) AddGeoMeta(code string, start, length int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, info := range m.GeoMeta {
		if info.Code == code {
			return
		}
	}
	m.GeoMeta = append(m.GeoMeta, GeoMeta{Code: code, Start: int64(start), Length: int64(length)})
}

func (m *MMapFile) GetGeoMeta(code string) *GeoMeta {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, info := range m.GeoMeta {
		if info.Code == code {
			return &info
		}
	}
	return nil
}

func (m *MMapFile) unmapLocked() error {
	if m.data == nil {
		return nil
	}
	err := unix.Munmap(m.data)
	m.data = nil
	m.size = 0
	return err
}

func (m *MMapFile) buildGeoMetaList() {
	if platform.IsAssetMapEnabled() {
		m.buildGeoMetaFromMappedFile()
	} else {
		// set memory limit then unset

		oldLimit := debug.SetMemoryLimit(1 << 20)
		defer func() {
			debug.SetMemoryLimit(oldLimit)
		}()

		m.buildGeoMetaFromMemmory(func(code []byte, start, length int64) error {
			m.AddGeoMeta(string(code), int(start), int(length))
			runtime.GC()

			return nil
		})

	}
}

func (m *MMapFile) buildGeoMetaFromMemmory(onEntry func(code []byte, start, length int64) error) error {
	data := m.Bytes()
	baseLen := len(data)
	var off int64 = 0

	for {
		if len(data) < 2 {
			return nil
		}

		x, n := DecodeVarint(data[1:])
		if x == 0 && n == 0 {
			return nil
		}

		headL := 1 + n

		if x > uint64(len(data)-headL) {
			return fmt.Errorf("corrupt data: bodyLen=%d exceeds remaining=%d", x, len(data)-headL)
		}
		bodyL := int(x)

		body := data[headL : headL+bodyL]
		start := off + int64(headL)
		length := int64(bodyL)

		if len(body) >= 2 {
			codeL := int(body[1])
			if codeL > 0 && len(body) >= 2+codeL {
				code := body[2 : 2+codeL]

				if err := onEntry(code, start, length); err != nil {
					return err
				}
			}
		}

		step := headL + bodyL
		data = data[step:]
		off += int64(step)

		if off > int64(baseLen) {
			return fmt.Errorf("corrupt scan: offset overflow")
		}
	}
}

// the mapped file should be along side the geo file, if file is geosite.dat , mapped should be geosite.dat.map
func (m *MMapFile) buildGeoMetaFromMappedFile() error {
	f, err := os.Open(m.path + ".map")
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			return fmt.Errorf("invalid line: %q", line)
		}

		start, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid start byte in %q", line)
		}

		length, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid length in %q", line)
		}
		m.AddGeoMeta(parts[0], int(start), int(length))

	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

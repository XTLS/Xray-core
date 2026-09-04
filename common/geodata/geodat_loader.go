package geodata

import (
	"io"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"

	"google.golang.org/protobuf/proto"
)

// cachedFile holds the raw bytes of a .dat file and an index of its entries.
// The whole file is read sequentially once and kept in memory; entries are
// served as zero-copy slices of it. On routers with slow flash, a single
// sequential read per file is far cheaper than re-reading (random) entry
// ranges or re-scanning the file for every referenced code.
type cachedFile struct {
	data  []byte
	index map[string]entryRef
}

// entryRef locates one GeoIP/GeoSite entry within its .dat file.
type entryRef struct {
	off    int64
	length int64
}

// geoDataCache maps a .dat file name to its cached bytes and index.
var geoDataCache sync.Map

// ResetEntryCache drops all cached .dat files. It must be called when the
// .dat files are reloaded (see app/geodata) so a swapped file is picked up
// instead of serving stale cached entries.
func ResetEntryCache() {
	geoDataCache = sync.Map{}
}

func getCachedFile(file string) (*cachedFile, error) {
	if v, ok := geoDataCache.Load(file); ok {
		return v.(*cachedFile), nil
	}
	r, err := filesystem.OpenAsset(file)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		return nil, err
	}
	index, err := buildIndex(data)
	if err != nil {
		return nil, err
	}
	cf := &cachedFile{data: data, index: index}
	if v, ok := geoDataCache.LoadOrStore(file, cf); ok {
		return v.(*cachedFile), nil
	}
	return cf, nil
}

func loadEntry(file, code string) ([]byte, error) {
	cf, err := getCachedFile(file)
	if err != nil {
		return nil, err
	}
	ref, ok := cf.index[code]
	if !ok {
		return nil, io.EOF
	}
	return cf.data[ref.off : ref.off+ref.length], nil
}

// buildIndex scans a .dat file in memory and records the byte range of every
// entry whose code (first string field) is well-formed. The first occurrence
// of a code wins, matching the previous find() behavior.
func buildIndex(data []byte) (map[string]entryRef, error) {
	m := make(map[string]entryRef)
	for pos := 0; pos < len(data); {
		pos++ // skip field tag byte
		v, n, err := readVarint(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		if v <= 0 || pos+int(v) > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		payload := data[pos : pos+int(v)]
		if len(payload) >= 2 && int(payload[1]) <= len(payload)-2 {
			code := string(payload[2 : 2+int(payload[1])])
			if code != "" {
				if _, exists := m[code]; !exists {
					m[code] = entryRef{off: int64(pos), length: int64(v)}
				}
			}
		}
		pos += int(v)
	}
	if len(m) == 0 {
		return nil, errors.New("no entries found in file")
	}
	return m, nil
}

// readVarint decodes a protobuf varint from a byte slice, returning the value
// and the number of bytes consumed.
func readVarint(b []byte) (uint64, int, error) {
	var x uint64
	for i := 0; i < 10; i++ {
		if i >= len(b) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		c := b[i]
		x |= (uint64(c) & 0x7F) << (7 * i)
		if (c & 0x80) == 0 {
			return x, i + 1, nil
		}
	}
	return 0, 0, errors.New("varint overflow")
}

func checkFile(file, code string) error {
	if _, err := loadEntry(file, code); err != nil {
		return errors.New("failed to check code ", code, " from ", file).Base(err)
	}
	return nil
}

func loadFile(file, code string) ([]byte, error) {
	bs, err := loadEntry(file, code)
	if err != nil {
		return nil, errors.New("failed to load code ", code, " from ", file).Base(err)
	}
	return bs, nil
}

func loadIP(file, code string) ([]*CIDR, error) {
	bs, err := loadFile(file, code)
	if err != nil {
		return nil, err
	}
	var geoip GeoIP
	if err := proto.Unmarshal(bs, &geoip); err != nil {
		return nil, errors.New("error unmarshal IP in ", file, ":", code).Base(err)
	}
	return geoip.Cidr, nil
}

func loadSite(file, code string) ([]*Domain, error) {
	bs, err := loadFile(file, code)
	if err != nil {
		return nil, err
	}
	var geosite GeoSite
	if err := proto.Unmarshal(bs, &geosite); err != nil {
		return nil, errors.New("error unmarshal Site in ", file, ":", code).Base(err)
	}
	return geosite.Domain, nil
}

type AttributeMatcher interface {
	Match(*Domain) bool
}

type HasAttrMatcher string

// Match reports whether this matcher matches any attribute on the domain.
func (m HasAttrMatcher) Match(domain *Domain) bool {
	for _, attr := range domain.Attribute {
		if attr.Key == string(m) {
			return true
		}
	}
	return false
}

type AllAttrsMatcher struct {
	matchers []AttributeMatcher
}

// Match reports whether the domain matches every matcher in the list.
func (m *AllAttrsMatcher) Match(domain *Domain) bool {
	for _, matcher := range m.matchers {
		if !matcher.Match(domain) {
			return false
		}
	}
	return true
}

func NewAllAttrsMatcher(attrs string) AttributeMatcher {
	if attrs == "" {
		return nil
	}
	m := new(AllAttrsMatcher)
	for _, attr := range strings.Split(attrs, "@") {
		m.matchers = append(m.matchers, HasAttrMatcher(attr))
	}
	return m
}

func loadSiteWithAttrs(file, code, attrs string) ([]*Domain, error) {
	domains, err := loadSite(file, code)
	if err != nil {
		return nil, err
	}

	matcher := NewAllAttrsMatcher(attrs)
	if matcher == nil {
		return domains, nil
	}

	filtered := make([]*Domain, 0, len(domains))
	for _, d := range domains {
		if matcher.Match(d) {
			filtered = append(filtered, d)
		}
	}

	return filtered, nil
}

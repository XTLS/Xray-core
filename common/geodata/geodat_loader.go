package geodata

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/utils"

	"google.golang.org/protobuf/proto"
)

// entryCache caches the raw protobuf bytes of a single GeoIP/GeoSite entry,
// keyed by file name and entry code. fileIndexCache caches, per file, a map of
// entry code to its byte range within the file, built with a single pass over
// the file. Together they turn the previous per-rule behavior (a full linear
// scan of the .dat file per referenced code, both at parse time via checkFile
// and at matcher build time via loadIP/loadSite) into one read and one scan
// per file, with each referenced entry read from disk at most once.
var (
	entryCache     = utils.NewWeakCacheMap[string, []byte]()
	fileIndexCache = utils.NewWeakCacheMap[string, map[string]entryRef]()
)

// entryRef locates one GeoIP/GeoSite entry within its .dat file.
type entryRef struct {
	off    int64
	length int64
}

// ResetEntryCache drops all cached GeoIP/GeoSite entries and file indexes. It
// must be called when the .dat files are reloaded (see app/geodata) so a
// swapped file is picked up instead of serving stale cached entries.
func ResetEntryCache() {
	entryCache = utils.NewWeakCacheMap[string, []byte]()
	fileIndexCache = utils.NewWeakCacheMap[string, map[string]entryRef]()
}

func loadEntry(file, code string) ([]byte, error) {
	key := file + "\x00" + code
	if bs, ok := entryCache.Load(key); ok {
		return *bs, nil
	}
	idx, err := indexFile(file)
	if err != nil {
		return nil, err
	}
	ref, ok := idx[code]
	if !ok {
		return nil, io.EOF
	}
	bs, err := readEntry(file, code, ref)
	if err != nil {
		return nil, err
	}
	entryCache.Store(key, &bs)
	return bs, nil
}

// indexFile builds a code->entry index for a .dat file in a single streaming
// pass. Only a small prefix of each entry is read; the rest is discarded, so
// the transient memory cost stays tiny.
func indexFile(file string) (map[string]entryRef, error) {
	if m, ok := fileIndexCache.Load(file); ok {
		return *m, nil
	}
	r, err := filesystem.OpenAsset(file)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	br := bufio.NewReaderSize(r, 64*1024)

	// maxCodeLen bounds the entry-code prefix buffer. Real v2ray/XTLS .dat
	// entry codes are short; a longer code just means the entry is skipped
	// from the index (it would not have matched find() for any queried code
	// shorter than the buffer either).
	const maxCodeLen = 64
	head := make([]byte, 2+maxCodeLen)

	m := make(map[string]entryRef)
	var pos int64
	for {
		if _, err := br.ReadByte(); err != nil { // field tag
			if err == io.EOF {
				break
			}
			return nil, err
		}
		bodyL, n, err := decodeVarintCount(br)
		if err != nil {
			return nil, err
		}
		if bodyL <= 0 {
			return nil, errors.New("invalid body length: ", bodyL)
		}
		if uint64(int64(^uint64(0)>>1)) < bodyL {
			return nil, io.ErrUnexpectedEOF
		}
		bl := int64(bodyL)

		need := int(bl)
		if need > len(head) {
			need = len(head)
		}
		codeLen := 0
		if _, err := io.ReadFull(br, head[:need]); err != nil {
			return nil, err
		}
		if need >= 2 && 2+int(head[1]) <= need {
			codeLen = int(head[1])
		}
		if rest := int(bl) - need; rest > 0 {
			if _, err := br.Discard(rest); err != nil {
				return nil, err
			}
		}
		pos += 1 + int64(n) + bl

		if codeLen > 0 {
			code := string(head[2 : 2+codeLen])
			if _, exists := m[code]; !exists {
				m[code] = entryRef{off: pos - bl, length: bl}
			}
		}
	}
	if len(m) == 0 {
		return nil, errors.New("no entries found in file")
	}
	fileIndexCache.Store(file, &m)
	return m, nil
}

// readEntry returns the raw bytes of the entry at ref. It prefers a random
// access read (the asset file is an *os.File); otherwise it falls back to the
// streaming scan.
func readEntry(file, code string, ref entryRef) ([]byte, error) {
	r, err := filesystem.OpenAsset(file)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if ra, ok := r.(io.ReaderAt); ok {
		bs := make([]byte, ref.length)
		if _, err := ra.ReadAt(bs, ref.off); err != nil {
			return nil, err
		}
		return bs, nil
	}
	return find(r, []byte(code), true)
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

func decodeVarint(br *bufio.Reader) (uint64, error) {
	var x uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		x |= (uint64(b) & 0x7F) << shift
		if (b & 0x80) == 0 {
			return x, nil
		}
	}
	// The number is too large to represent in a 64-bit value.
	return 0, errors.New("varint overflow")
}

// decodeVarintCount decodes a protobuf varint from a buffered reader, also
// returning the number of bytes consumed.
func decodeVarintCount(br *bufio.Reader) (uint64, int64, error) {
	var x uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b, err := br.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		x |= (uint64(b) & 0x7F) << shift
		if (b & 0x80) == 0 {
			return x, int64(shift/7 + 1), nil
		}
	}
	return 0, 0, errors.New("varint overflow")
}

func find(r io.Reader, code []byte, readBody bool) ([]byte, error) {
	codeL := len(code)
	if codeL == 0 {
		return nil, errors.New("empty code")
	}

	br := bufio.NewReaderSize(r, 64*1024)
	need := 2 + codeL // TODO: if code too long
	prefixBuf := make([]byte, need)

	for {
		if _, err := br.ReadByte(); err != nil {
			return nil, err
		}

		x, err := decodeVarint(br)
		if err != nil {
			return nil, err
		}
		bodyL := int(x)
		if bodyL <= 0 {
			return nil, errors.New("invalid body length: ", bodyL)
		}

		prefixL := bodyL
		if prefixL > need {
			prefixL = need
		}
		prefix := prefixBuf[:prefixL]
		if _, err := io.ReadFull(br, prefix); err != nil {
			return nil, err
		}

		match := false
		if bodyL >= need {
			if int(prefix[1]) == codeL && bytes.Equal(prefix[2:need], code) {
				if !readBody {
					return nil, nil
				}
				match = true
			}
		}

		remain := bodyL - prefixL
		if match {
			out := make([]byte, bodyL)
			copy(out, prefix)
			if remain > 0 {
				if _, err := io.ReadFull(br, out[prefixL:]); err != nil {
					return nil, err
				}
			}
			return out, nil
		}

		if remain > 0 {
			if _, err := br.Discard(remain); err != nil {
				return nil, err
			}
		}
	}
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

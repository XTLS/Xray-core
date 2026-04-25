package geodata

import (
	"bufio"
	"bytes"
	"io"
	"runtime"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"

	"google.golang.org/protobuf/proto"
)

func checkFile(file, code string) error {
	r, err := filesystem.OpenAsset(file)
	if err != nil {
		return errors.New("failed to open ", file).Base(err)
	}
	defer r.Close()
	if _, err := find(r, []byte(code), false); err != nil {
		return errors.New("failed to check code ", code, " from ", file).Base(err)
	}
	return nil
}

func loadFile(file, code string) ([]byte, error) {
	runtime.GC() // peak mem
	r, err := filesystem.OpenAsset(file)
	if err != nil {
		return nil, errors.New("failed to open ", file).Base(err)
	}
	defer r.Close()
	bs, err := find(r, []byte(code), true)
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
	defer runtime.GC() // peak mem
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
	defer runtime.GC() // peak mem
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

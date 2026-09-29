package geodata

import (
	"bufio"
	"bytes"
	"io"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"

	"google.golang.org/protobuf/encoding/protowire"
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

// loadSite calls fn, in file order, with the type and value of every domain of the geosite code
// that has all the "@"-separated attrs. It decodes the entry while reading the file instead of
// unmarshalling it into a []*Domain, so value is only valid during fn.
func loadSite(file, code, attrs string, fn func(Domain_Type, []byte)) error {
	runtime.GC() // peak mem
	r, err := filesystem.OpenAsset(file)
	if err != nil {
		return errors.New("failed to open ", file).Base(err)
	}
	defer r.Close()
	br := bufio.NewReaderSize(r, 64*1024)
	n, err := seek(br, []byte(code))
	if err != nil {
		return errors.New("failed to load code ", code, " from ", file).Base(err)
	}
	loadErr := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return errors.New("failed to load code ", code, " from ", file).Base(err)
	}
	unmarshalErr := func(err error) error {
		return errors.New("error unmarshal Site in ", file, ":", code).Base(err)
	}
	d := newSiteDecoder(attrs, fn)
	for n > 0 {
		w, err := br.Peek(min(n, br.Size()))
		if err != nil {
			return loadErr(err)
		}
		used, err := d.decode(w, len(w) < n)
		if err != nil {
			return unmarshalErr(err)
		}
		if used == 0 {
			break // a field longer than the buffer
		}
		br.Discard(used)
		n -= used
	}
	if n > 0 {
		w := make([]byte, n)
		if _, err := io.ReadFull(br, w); err != nil {
			return loadErr(err)
		}
		if _, err := d.decode(w, false); err != nil {
			return unmarshalErr(err)
		}
	}
	return nil
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
	br := bufio.NewReaderSize(r, 64*1024)
	bodyL, err := seek(br, code)
	if err != nil || !readBody {
		return nil, err
	}
	out := make([]byte, bodyL)
	if _, err := io.ReadFull(br, out); err != nil {
		return nil, err
	}
	return out, nil
}

// seek advances br to the body of the entry for code and returns the body length.
func seek(br *bufio.Reader, code []byte) (int, error) {
	codeL := len(code)
	if codeL == 0 {
		return 0, errors.New("empty code")
	}
	need := 2 + codeL // TODO: if code too long

	for {
		if _, err := br.ReadByte(); err != nil {
			return 0, err
		}

		x, err := decodeVarint(br)
		if err != nil {
			return 0, err
		}
		bodyL := int(x)
		if bodyL <= 0 {
			return 0, errors.New("invalid body length: ", bodyL)
		}

		// Peek no more than the buffer holds: a code longer than the buffer cannot match a single
		// length byte anyway, so a short peek only skips it, as base find (io.ReadFull) does.
		prefix, err := br.Peek(min(bodyL, need, br.Size()))
		if err != nil {
			if err == io.EOF && len(prefix) > 0 {
				err = io.ErrUnexpectedEOF // as io.ReadFull
			}
			return 0, err
		}
		if bodyL >= need && len(prefix) >= need && int(prefix[1]) == codeL && bytes.Equal(prefix[2:], code) {
			return bodyL, nil
		}
		if _, err := br.Discard(bodyL); err != nil {
			return 0, err
		}
	}
}

// AttributeMatcher, HasAttrMatcher, AllAttrsMatcher and NewAllAttrsMatcher are the exported
// attribute helpers that have been part of this package's API since #5814. The streaming loader
// above filters attributes itself without building a *Domain, so it does not use them, but they
// are kept for external callers. Their behaviour is unchanged.

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

var errInvalidUTF8 = errors.New("string field contains invalid UTF-8")

type siteDecoder struct {
	want []string
	has  []bool
	fn   func(Domain_Type, []byte)
}

func newSiteDecoder(attrs string, fn func(Domain_Type, []byte)) *siteDecoder {
	d := &siteDecoder{fn: fn}
	if attrs != "" {
		d.want = strings.Split(attrs, "@")
		d.has = make([]bool, len(d.want))
	}
	return d
}

// decode walks the whole fields at the start of b, a part of an encoded GeoSite (see geodat.proto),
// calls fn for every domain that has all attrs and returns how many bytes it used. A field cut off
// by the end of b is an error unless more is set. It accepts and rejects what proto.Unmarshal does.
func (d *siteDecoder) decode(b []byte, more bool) (int, error) {
	used := 0
	for used < len(b) {
		f, n, err := consumeField(b[used:])
		if err == io.ErrUnexpectedEOF && more {
			break
		}
		if err != nil {
			return used, err
		}
		used += n
		if f.typ != protowire.BytesType {
			continue
		}
		switch f.num {
		case 1: // code
			if !utf8.Valid(f.v) {
				return used, errInvalidUTF8
			}
		case 2: // domain
			t, value, err := decodeDomain(f.v, d.want, d.has)
			if err != nil {
				return used, err
			}
			if !slices.Contains(d.has, false) {
				d.fn(t, value)
			}
		}
	}
	return used, nil
}

// decodeDomain decodes an encoded Domain and sets has[i] if one of its attributes has the key want[i].
func decodeDomain(b []byte, want []string, has []bool) (t Domain_Type, value []byte, err error) {
	clear(has)
	for len(b) > 0 {
		f, n, err := consumeField(b)
		if err != nil {
			return 0, nil, err
		}
		b = b[n:]
		switch {
		case f.num == 1 && f.typ == protowire.VarintType: // type
			t = Domain_Type(f.x)
		case f.num == 2 && f.typ == protowire.BytesType: // value
			if !utf8.Valid(f.v) {
				return 0, nil, errInvalidUTF8
			}
			value = f.v
		case f.num == 3 && f.typ == protowire.BytesType: // attribute
			key, err := decodeAttributeKey(f.v)
			if err != nil {
				return 0, nil, err
			}
			for i, w := range want {
				if string(key) == w {
					has[i] = true
				}
			}
		}
	}
	return t, value, nil
}

// decodeAttributeKey returns the key of an encoded Domain.Attribute.
func decodeAttributeKey(b []byte) ([]byte, error) {
	var key []byte
	for len(b) > 0 {
		f, n, err := consumeField(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if f.num == 1 && f.typ == protowire.BytesType {
			if !utf8.Valid(f.v) {
				return nil, errInvalidUTF8
			}
			key = f.v
		}
	}
	return key, nil
}

type protoField struct {
	num protowire.Number
	typ protowire.Type
	v   []byte // payload of a length-delimited field
	x   uint64 // value of a varint field
}

// consumeField parses the first field of an encoded message and returns it with its length.
func consumeField(b []byte) (protoField, int, error) {
	num, typ, n := protowire.ConsumeTag(b)
	if n < 0 {
		return protoField{}, 0, protowire.ParseError(n)
	}
	if num > protowire.MaxValidNumber {
		return protoField{}, 0, errors.New("invalid field number ", num)
	}
	f := protoField{num: num, typ: typ}
	var m int
	switch typ {
	case protowire.BytesType:
		f.v, m = protowire.ConsumeBytes(b[n:])
	case protowire.VarintType:
		f.x, m = protowire.ConsumeVarint(b[n:])
	default:
		m = protowire.ConsumeFieldValue(num, typ, b[n:])
	}
	if m < 0 {
		return protoField{}, 0, protowire.ParseError(m)
	}
	return f, n + m, nil
}

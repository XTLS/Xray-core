package geodata

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type siteEntry struct {
	Type  Domain_Type
	Value string
}

// unmarshalSite is what loadSite used to do: proto.Unmarshal, then keep the domains that have all attrs.
func unmarshalSite(b []byte, attrs string) ([]siteEntry, error) {
	var site GeoSite
	if err := proto.Unmarshal(b, &site); err != nil {
		return nil, err
	}
	var entries []siteEntry
	for _, d := range site.Domain {
		ok := true
		for _, key := range strings.Split(attrs, "@") {
			ok = ok && (attrs == "" || slices.ContainsFunc(d.Attribute, func(a *Domain_Attribute) bool { return a.Key == key }))
		}
		if ok {
			entries = append(entries, siteEntry{d.Type, d.Value})
		}
	}
	return entries, nil
}

func checkDecodeSite(t *testing.T, name string, b []byte, attrs string) {
	t.Helper()
	want, wantErr := unmarshalSite(b, attrs)
	var got []siteEntry
	_, err := newSiteDecoder(attrs, func(typ Domain_Type, value []byte) {
		got = append(got, siteEntry{typ, string(value)})
	}).decode(b, false)
	if (err == nil) != (wantErr == nil) {
		t.Fatalf("%s@%s: error %v, proto.Unmarshal: %v", name, attrs, err, wantErr)
	}
	if err == nil && !slices.Equal(got, want) {
		t.Fatalf("%s@%s: got %v, want %v", name, attrs, got, want)
	}
}

func TestDecodeSiteMatchesUnmarshal(t *testing.T) {
	bs, err := os.ReadFile(filepath.Join("..", "..", "resources", DefaultGeoSiteDat))
	if err != nil {
		t.Fatal(err)
	}
	for len(bs) > 0 {
		num, typ, n := protowire.ConsumeTag(bs)
		if n < 0 || num != 1 || typ != protowire.BytesType {
			t.Fatal("unexpected GeoSiteList field")
		}
		entry, m := protowire.ConsumeBytes(bs[n:])
		if m < 0 {
			t.Fatal(protowire.ParseError(m))
		}
		bs = bs[n+m:]

		var site GeoSite
		if err := proto.Unmarshal(entry, &site); err != nil {
			t.Fatal(err)
		}
		queries := []string{"", "none"}
		for _, d := range site.Domain {
			for _, a := range d.Attribute {
				if !slices.Contains(queries, a.Key) {
					queries = append(queries, a.Key, a.Key+"@none")
				}
			}
		}
		for _, attrs := range queries {
			checkDecodeSite(t, site.Code, entry, attrs)
		}
	}
}

func TestDecodeSiteUnusualEncodings(t *testing.T) {
	field := func(num protowire.Number, v []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), v)
	}
	typ := func(v Domain_Type) []byte {
		return protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), uint64(v))
	}
	value := func(s string) []byte { return field(2, []byte(s)) }
	attr := func(keys ...string) []byte {
		var b []byte
		for _, k := range keys {
			b = append(b, field(1, []byte(k))...)
		}
		return field(3, b)
	}
	domain := func(fields ...[]byte) []byte { return field(2, slices.Concat(fields...)) }
	unknown := protowire.AppendFixed32(protowire.AppendTag(nil, 9, protowire.Fixed32Type), 1)

	for name, b := range map[string][]byte{
		"unknown field":   domain(typ(Domain_Full), unknown, value("example.com")),
		"repeated value":  domain(value("a.com"), typ(Domain_Full), value("b.com")),
		"repeated type":   domain(typ(Domain_Full), value("a.com"), typ(Domain_Regex)),
		"repeated key":    domain(value("a.com"), attr("cn", "ads")),
		"type as bytes":   domain(field(1, []byte("x")), value("a.com")),
		"no value":        domain(typ(Domain_Domain), attr("cn")),
		"truncated":       domain(typ(Domain_Full), value("example.com"))[:10],
		"invalid utf8":    domain(value("example.\xff")),
		"invalid key":     domain(value("a.com"), attr("\xff")),
		"bad field":       protowire.AppendVarint(protowire.AppendTag(nil, protowire.MaxValidNumber+1, protowire.VarintType), 1),
		"stray end group": protowire.AppendTag(nil, 5, protowire.EndGroupType),
	} {
		for _, attrs := range []string{"", "cn", "ads", "cn@ads"} {
			checkDecodeSite(t, name, b, attrs)
		}
	}
}

// TestLoadSiteReadsInPieces covers what real lists never do: an entry far longer than the read
// buffer, with a field longer than the buffer in the middle, and a file cut short.
func TestLoadSiteReadsInPieces(t *testing.T) {
	site := &GeoSite{Code: "BIG"}
	for i := range 5000 {
		d := &Domain{Type: Domain_Domain, Value: strings.Repeat("x", i%40) + ".example.com"}
		if i%3 == 0 {
			d.Attribute = []*Domain_Attribute{{Key: "cn"}}
		}
		if i == 2500 {
			d = &Domain{Type: Domain_Regex, Value: strings.Repeat("a", 100_000)}
		}
		site.Domain = append(site.Domain, d)
	}
	list := &GeoSiteList{Entry: []*GeoSite{{Code: "SMALL", Domain: []*Domain{{Type: Domain_Full, Value: "a.com"}}}, site}}
	bs, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := proto.Marshal(site)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	write := func(b []byte) {
		if err := os.WriteFile(filepath.Join(dir, "big.dat"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, attrs := range []string{"", "cn"} {
		want, _ := unmarshalSite(entry, attrs)
		var got []siteEntry
		write(bs)
		err := loadSite("big.dat", "BIG", attrs, func(typ Domain_Type, value []byte) {
			got = append(got, siteEntry{typ, string(value)})
		})
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("attrs %q: %d entries, want %d, error %v", attrs, len(got), len(want), err)
		}
		for _, cut := range []int{30_000, len(bs) - 150_000, len(bs) - 1} {
			write(bs[:cut])
			if err := loadSite("big.dat", "BIG", attrs, func(Domain_Type, []byte) {}); err == nil {
				t.Fatalf("file cut at %d of %d: no error", cut, len(bs))
			}
		}
	}
}

// oneEntryGeoSiteFile wraps an encoded GeoSite as a one-entry GeoSiteList, the file loadSite reads.
func oneEntryGeoSiteFile(entry []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), entry)
}

// TestLoadSiteWindowedMatchesSingleShot checks that the windowed reader in loadSite (its Peek/Discard
// loop, the more-break when a field is cut by a window edge, the used==0 fallback for a field longer
// than the buffer, and the tail path) reaches exactly the same result as decoding the whole entry at
// once, for a category several 64 KiB windows long, valid and then mutated near a window edge and
// early in the file: same error-or-not, and the same emitted (type, value) sequence when both accept.
func TestLoadSiteWindowedMatchesSingleShot(t *testing.T) {
	const window = 64 * 1024
	site := &GeoSite{Code: "BIG"}
	for i := range 12000 { // ~250 KiB, four windows
		d := &Domain{Type: Domain_Domain, Value: fmt.Sprintf("host%d.%s.example.com", i, strings.Repeat("y", i%30))}
		if i%3 == 0 {
			d.Attribute = []*Domain_Attribute{{Key: "cn"}}
		}
		site.Domain = append(site.Domain, d)
	}
	// a field longer than the buffer, straddling the third window, to force the used==0 fallback
	site.Domain = slices.Insert(site.Domain, 8000, &Domain{Type: Domain_Regex, Value: strings.Repeat("a", 90_000)})
	entry, err := proto.Marshal(site)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)

	// mutations of the encoded entry: unchanged, a byte flipped at several offsets (early windows and
	// either side of a window edge), and truncations at the same places.
	type mut struct {
		name string
		make func([]byte) []byte
	}
	muts := []mut{{"valid", func(b []byte) []byte { return b }}}
	for _, off := range []int{3, 40, 4000, window - 1, window, window + 1, 2*window - 2, 2 * window} {
		if off < len(entry) {
			off := off
			muts = append(muts, mut{fmt.Sprintf("flip@%d", off), func(b []byte) []byte {
				c := slices.Clone(b)
				c[off] ^= 0xff
				return c
			}})
			muts = append(muts, mut{fmt.Sprintf("cut@%d", off), func(b []byte) []byte { return slices.Clone(b[:off]) }})
		}
	}

	for _, attrs := range []string{"", "cn"} {
		for _, m := range muts {
			e := m.make(entry)
			// single-shot reference: decode the whole entry in one call
			var want []siteEntry
			_, wantErr := newSiteDecoder(attrs, func(typ Domain_Type, value []byte) {
				want = append(want, siteEntry{typ, string(value)})
			}).decode(e, false)
			// windowed: loadSite reads the file 64 KiB at a time
			if err := os.WriteFile(filepath.Join(dir, "w.dat"), oneEntryGeoSiteFile(e), 0o644); err != nil {
				t.Fatal(err)
			}
			var got []siteEntry
			gotErr := loadSite("w.dat", "BIG", attrs, func(typ Domain_Type, value []byte) {
				got = append(got, siteEntry{typ, string(value)})
			})
			if (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("%s attrs=%q: windowed err %v, single-shot err %v", m.name, attrs, gotErr, wantErr)
			}
			if gotErr == nil && !slices.Equal(got, want) {
				t.Fatalf("%s attrs=%q: windowed got %d entries, single-shot %d", m.name, attrs, len(got), len(want))
			}
		}
	}
}

// TestLoadSiteLongCode covers a geosite entry whose code is longer than the 64 KiB read buffer. seek
// must skip it (find compares a single length byte, so it never matches such a code) and still find a
// later entry, and looking the long code up must fail cleanly, like a missing code, not panic.
func TestLoadSiteLongCode(t *testing.T) {
	longCode := strings.Repeat("Z", 70000)
	list := &GeoSiteList{Entry: []*GeoSite{
		{Code: "FIRST", Domain: []*Domain{{Type: Domain_Full, Value: "first.com"}}},
		{Code: longCode, Domain: []*Domain{{Type: Domain_Full, Value: "huge.com"}}},
		{Code: "AFTER", Domain: []*Domain{{Type: Domain_Domain, Value: "after.com"}}},
	}}
	bs, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	if err := os.WriteFile(filepath.Join(dir, "lc.dat"), bs, 0o644); err != nil {
		t.Fatal(err)
	}
	collect := func(code string) ([]siteEntry, error) {
		var got []siteEntry
		err := loadSite("lc.dat", code, "", func(typ Domain_Type, value []byte) {
			got = append(got, siteEntry{typ, string(value)})
		})
		return got, err
	}
	if got, err := collect("FIRST"); err != nil || !slices.Equal(got, []siteEntry{{Domain_Full, "first.com"}}) {
		t.Fatalf("FIRST: %v %v", got, err)
	}
	if got, err := collect("AFTER"); err != nil || !slices.Equal(got, []siteEntry{{Domain_Domain, "after.com"}}) {
		t.Fatalf("AFTER (past the oversized entry): %v %v", got, err)
	}
	if _, err := collect(longCode); err == nil {
		t.Fatal("oversized code: expected a not-found error, got nil")
	}
}

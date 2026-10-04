package strmatcher

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"strings"
	"unsafe"
)

// Flags of a level1 slot, stored above the record offset.
const (
	mphDomain  = 1 << 31 // matches the pattern and its subdomains
	mphFull    = 1 << 30 // matches the pattern only
	mphParent  = 1 << 29 // matches subdomains only, from a pattern with a leading dot
	mphOffMask = mphParent - 1
)

// Kinds of an added pattern, indexes of mphKinds.
const (
	mphKindFull = iota
	mphKindParent
	mphKindDomain
)

// mphKinds are the slot flags in the order Match reports their values.
var mphKinds = [...]uint32{mphFull, mphParent, mphDomain}

// mphMultipliers are odd multipliers for the suffix hash. Build moves to the next one if two patterns collide.
var mphMultipliers = [...]uint64{0x9e3779b97f4a7c15, 0xc2b2ae3d27d4eb4f, 0x165667b19e3779f9, 0x27d4eb2f165667c5}

var (
	errMphCollision = errors.New("strmatcher: suffix hash collision in MphMatcherGroup")
	errMphBuilt     = errors.New("strmatcher: MphMatcherGroup is already built")
)

type mphEntry struct {
	off   uint32 // pattern start in buf
	value uint32
	n     uint32 // pattern length
	kind  uint8
}

// MphMatcherGroup is an implementation of MatcherGroup for Full and Domain matchers.
// Each distinct pattern is stored once as a record in arena: its length (255 means a uvarint length follows),
// its bytes and, if the group holds more than one distinct value, its values. A minimal perfect hash table
// built with hash, displace and compress (http://cmph.sourceforge.net/papers/esa09.pdf) maps a pattern to its
// record. Patterns are hashed from the right, so one pass over the input hashes all its parent domains.
type MphMatcherGroup struct {
	arena  string
	level0 []uint16 // bucket -> seed
	level1 []uint32 // slot -> flags | record offset
	fp     []uint8  // slot -> low byte of its pattern's hash, rejects most misses without reading arena
	n0, n1 uint32
	mul    uint64 // multiplier of the suffix hash
	single uint32 // the only value if !multi
	multi  bool

	buf     []byte // build only, patterns in Add order
	entries []mphEntry
}

func NewMphMatcherGroup() *MphMatcherGroup {
	return new(MphMatcherGroup)
}

// AddFullMatcher implements MatcherGroupForFull.
func (g *MphMatcherGroup) AddFullMatcher(matcher FullMatcher, value uint32) {
	g.add(matcher.Pattern(), mphKindFull, value)
}

// AddDomainMatcher implements MatcherGroupForDomain.
func (g *MphMatcherGroup) AddDomainMatcher(matcher DomainMatcher, value uint32) {
	g.add(matcher.Pattern(), mphKindDomain, value)
}

func (g *MphMatcherGroup) add(pattern string, kind uint8, value uint32) {
	if g.arena != "" {
		panic(errMphBuilt)
	}
	pattern = strings.ToLower(pattern)
	off := uint32(len(g.buf))
	g.buf = append(g.buf, pattern...)
	g.entries = append(g.entries, mphEntry{off: off, value: value, n: uint32(len(pattern)), kind: kind})
	if len(pattern) > 0 && pattern[0] == '.' {
		// ".x" has always matched "*.x" as well, so it also gets a parent-only record for "x"
		g.entries = append(g.entries, mphEntry{off: off + 1, value: value, n: uint32(len(pattern) - 1), kind: mphKindParent})
	}
}

func (g *MphMatcherGroup) key(i uint32) []byte {
	e := &g.entries[i]
	return g.buf[e.off : e.off+e.n]
}

// Build builds the hash table. It must be called once, after the last Add.
func (g *MphMatcherGroup) Build() error {
	if g.arena != "" {
		return errMphBuilt
	}
	if uint64(len(g.buf)) > math.MaxUint32 {
		return errors.New("too many rules for MphMatcherGroup")
	}
	recs := g.writeRecords()
	if len(g.arena) > mphOffMask {
		return errors.New("too many rules for MphMatcherGroup")
	}
	hashes := make([]uint64, len(recs))
	for _, mul := range mphMultipliers {
		for i, rec := range recs {
			hashes[i] = mphMix(mphHash(mul, g.recKey(rec)))
		}
		g.mul = mul
		if err := g.place(recs, hashes); err != errMphCollision {
			return err
		}
	}
	return errMphCollision
}

// writeRecords writes one record per distinct pattern to arena and returns flags | offset of each.
func (g *MphMatcherGroup) writeRecords() []uint32 {
	g.multi = false
	if len(g.entries) > 0 {
		g.single = g.entries[0].value
		for _, e := range g.entries {
			if e.value != g.single {
				g.multi = true
				break
			}
		}
	}
	// Equal patterns become neighbours in Add order, so their values keep their priority
	order := make([]uint32, len(g.entries))
	for i := range order {
		order[i] = uint32(i)
	}
	slices.SortFunc(order, func(a, b uint32) int {
		return cmp.Or(bytes.Compare(g.key(a), g.key(b)), cmp.Compare(a, b))
	})

	size := len(g.buf) + len(g.entries) + 2
	if g.multi {
		size += 3 * len(g.entries)
	}
	arena := make([]byte, 0, size)
	recs := make([]uint32, 0, len(order))
	var vals [len(mphKinds)][]uint32
	for i := 0; i < len(order); {
		k := g.key(order[i])
		for t := range vals {
			vals[t] = vals[t][:0]
		}
		for ; i < len(order) && bytes.Equal(g.key(order[i]), k); i++ {
			e := &g.entries[order[i]]
			if !slices.Contains(vals[e.kind], e.value) {
				vals[e.kind] = append(vals[e.kind], e.value)
			}
		}
		rec := uint32(len(arena))
		if len(k) < 255 {
			arena = append(arena, byte(len(k)))
		} else {
			arena = binary.AppendUvarint(append(arena, 255), uint64(len(k)))
		}
		arena = append(arena, k...)
		for t, v := range vals {
			if len(v) == 0 {
				continue
			}
			rec |= mphKinds[t]
			if g.multi {
				arena = binary.AppendUvarint(arena, uint64(len(v)))
				for _, x := range v {
					arena = binary.AppendUvarint(arena, uint64(x))
				}
			}
		}
		recs = append(recs, rec)
	}
	// Lookups may point one byte past a pattern, and an empty group needs a record at offset 0 for empty slots
	arena = append(arena, 0)
	if len(recs) == 0 {
		arena = append(arena, 0)
	}
	g.buf, g.entries = nil, nil
	if cap(arena)-len(arena) > len(arena)/32 {
		arena = slices.Clone(arena)
	}
	g.arena = unsafe.String(unsafe.SliceData(arena), len(arena)) // arena is not written after this
	return recs
}

// place fills level0, level1 and fp: records are bucketed by hash, and each bucket, largest first, gets
// the first seed that puts all its records in free slots.
func (g *MphMatcherGroup) place(recs []uint32, hashes []uint64) error {
	r := len(recs)
	n0, n1 := max(1, r/3), max(1, r+r/99)
	g.n0, g.n1 = uint32(n0), uint32(n1)
	g.level0 = make([]uint16, n0)
	g.level1 = make([]uint32, n1)
	g.fp = make([]uint8, n1)

	start := make([]uint32, n0+1)
	for _, h := range hashes {
		start[g.bucket(h)+1]++
	}
	for b := range n0 {
		start[b+1] += start[b]
	}
	members := make([]uint32, r)
	fill := slices.Clone(start[:n0])
	for i, h := range hashes {
		b := g.bucket(h)
		members[fill[b]] = uint32(i)
		fill[b]++
	}
	fill = nil
	buckets := make([]uint32, n0)
	for b := range buckets {
		buckets[b] = uint32(b)
	}
	slices.SortStableFunc(buckets, func(a, b uint32) int {
		return cmp.Compare(start[b+1]-start[b], start[a+1]-start[a])
	})

	occupied := make([]uint64, (n1+63)/64)
	var slots []uint32
next:
	for _, b := range buckets {
		m := members[start[b]:start[b+1]]
		if len(m) == 0 {
			break
		}
		for i := range m {
			for j := range i {
				if hashes[m[i]] == hashes[m[j]] {
					return errMphCollision // no seed can separate them
				}
			}
		}
	search:
		for seed := range math.MaxUint16 + 1 {
			slots = slots[:0]
			for _, ri := range m {
				s := g.slot(hashes[ri], uint16(seed))
				if occupied[s/64]&(1<<(s%64)) != 0 || slices.Contains(slots, s) {
					continue search
				}
				slots = append(slots, s)
			}
			for k, ri := range m {
				s := slots[k]
				occupied[s/64] |= 1 << (s % 64)
				g.level1[s] = recs[ri]
				g.fp[s] = uint8(hashes[ri])
			}
			g.level0[b] = uint16(seed)
			continue next
		}
		return errors.New("strmatcher: no seed found for a bucket in MphMatcherGroup")
	}
	return nil
}

// mphHash is the suffix hash of s, taken from the right: the hash of s[i:] is the state after reading s[i].
func mphHash(mul uint64, s string) uint64 {
	h := uint64(0)
	for i := len(s) - 1; i >= 0; i-- {
		h = h*mul + uint64(s[i])
	}
	return h
}

// mphMix spreads the weak low bits of a suffix hash.
func mphMix(h uint64) uint64 {
	h ^= h >> 32
	h *= 0xd6e8feb86659fd93
	return h ^ h>>32
}

func (g *MphMatcherGroup) bucket(f uint64) uint32 {
	return uint32(((f >> 32) * uint64(g.n0)) >> 32)
}

func (g *MphMatcherGroup) slot(f uint64, seed uint16) uint32 {
	x := ((f ^ uint64(seed)*0x9e3779b97f4a7c15) * 0xc4ceb9fe1a85ec53) >> 32
	return uint32((x * uint64(g.n1)) >> 32)
}

func (g *MphMatcherGroup) uvarint(p uint32) (x, next uint32) {
	for shift := 0; ; shift += 7 {
		c := g.arena[p]
		p++
		x |= uint32(c&0x7f) << shift
		if c < 0x80 {
			return x, p
		}
	}
}

// recSpan returns where the pattern of the record at off starts and how long it is.
func (g *MphMatcherGroup) recSpan(off uint32) (p, n uint32) {
	n, p = uint32(g.arena[off]), off+1
	if n == 255 {
		n, p = g.uvarint(p)
	}
	return p, n
}

func (g *MphMatcherGroup) recKey(rec uint32) string {
	p, n := g.recSpan(rec & mphOffMask)
	return g.arena[p : p+n]
}

// lookup returns the level1 entry of s, or 0 if s is not a pattern. h is the suffix hash of s.
func (g *MphMatcherGroup) lookup(h uint64, s string) uint32 {
	f := mphMix(h)
	// bucket < n0 == len(level0) and slot < n1 == len(level1) == len(fp), skip the bounds checks
	seed := *(*uint16)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(g.level0)), uintptr(g.bucket(f))*2))
	slot := uintptr(g.slot(f, seed))
	if *(*uint8)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(g.fp)), slot)) != uint8(f) {
		return 0
	}
	e := *(*uint32)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(g.level1)), slot*4))
	if len(s) < 255 {
		// A record whose length byte is len(s) has len(s) pattern bytes after it
		p := unsafe.Add(unsafe.Pointer(unsafe.StringData(g.arena)), e&mphOffMask)
		if int(*(*byte)(p)) == len(s) && unsafe.String((*byte)(unsafe.Add(p, 1)), len(s)) == s {
			return e
		}
		return 0
	}
	if g.recKey(e) == s {
		return e
	}
	return 0
}

// appendValues appends the values of record e for the flags in want, in mphKinds order.
func (g *MphMatcherGroup) appendValues(dst []uint32, e, want uint32) []uint32 {
	if !g.multi {
		for _, flag := range mphKinds {
			if e&want&flag != 0 {
				dst = append(dst, g.single)
			}
		}
		return dst
	}
	if e&want == 0 {
		return dst
	}
	p, n := g.recSpan(e & mphOffMask)
	p += n
	for _, flag := range mphKinds {
		if e&flag == 0 {
			continue
		}
		var count, v uint32
		for count, p = g.uvarint(p); count > 0; count-- {
			v, p = g.uvarint(p)
			if want&flag != 0 {
				dst = append(dst, v)
			}
		}
	}
	return dst
}

// Match implements MatcherGroup.Match. Values of an exact match come first (Full, then Domain), then those of
// the parent domains, nearest first.
func (g *MphMatcherGroup) Match(input string) []uint32 {
	var stack [8]uint32
	parents := stack[:0] // TLD side first
	h, mul := uint64(0), g.mul
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == '.' {
			if e := g.lookup(h, input[i+1:]); e&(mphDomain|mphParent) != 0 {
				parents = append(parents, e)
			}
		}
		h = h*mul + uint64(input[i])
	}
	exact := g.lookup(h, input)
	if exact&(mphFull|mphDomain) == 0 && len(parents) == 0 {
		return nil
	}
	result := g.appendValues(make([]uint32, 0, len(parents)+1), exact, mphFull|mphDomain)
	for k := len(parents) - 1; k >= 0; k-- {
		result = g.appendValues(result, parents[k], mphParent|mphDomain)
	}
	return result
}

// MatchAny implements MatcherGroup.MatchAny.
func (g *MphMatcherGroup) MatchAny(input string) bool {
	h, mul := uint64(0), g.mul
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == '.' && g.lookup(h, input[i+1:])&(mphDomain|mphParent) != 0 {
			return true
		}
		h = h*mul + uint64(input[i])
	}
	return g.lookup(h, input)&(mphFull|mphDomain) != 0
}

// mphSuffix is the suffix hash of input[off:], a parent domain of the input.
type mphSuffix struct {
	h   uint64
	off int
}

// mphSuffixes appends the suffix hashes of the parent domains of input to dst, TLD side first, and returns them
// with the hash of input itself: what MatchAny computes, computed once for several groups.
func mphSuffixes(dst []mphSuffix, mul uint64, input string) ([]mphSuffix, uint64) {
	h := uint64(0)
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == '.' {
			dst = append(dst, mphSuffix{h, i + 1})
		}
		h = h*mul + uint64(input[i])
	}
	return dst, h
}

// matchAnyHashed is MatchAny with parents and h from mphSuffixes(_, mul, input).
func (g *MphMatcherGroup) matchAnyHashed(input string, parents []mphSuffix, h, mul uint64) bool {
	if g.mul != mul {
		return g.MatchAny(input) // built with a later multiplier after a collision
	}
	for _, p := range parents {
		if g.lookup(p.h, input[p.off:])&(mphDomain|mphParent) != 0 {
			return true
		}
	}
	return g.lookup(h, input)&(mphFull|mphDomain) != 0
}

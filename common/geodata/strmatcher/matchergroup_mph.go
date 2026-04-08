package strmatcher

import (
	"math/bits"
	"sort"
	"strings"
	"unsafe"
)

// PrimeRK is the prime base used in Rabin-Karp algorithm.
const PrimeRK = 16777619

// RollingHash calculates the rolling murmurHash of given string based on a provided suffix hash.
func RollingHash(hash uint32, input string) uint32 {
	for i := len(input) - 1; i >= 0; i-- {
		hash = hash*PrimeRK + uint32(input[i])
	}
	return hash
}

// MemHash is the hash function used by go map, it utilizes available hardware instructions(behaves
// as aeshash if aes instruction is available).
// With different seed, each MemHash<seed> performs as distinct hash functions.
func MemHash(seed uint32, input string) uint32 {
	return uint32(strhash(unsafe.Pointer(&input), uintptr(seed))) // nosemgrep
}

const (
	mphMatchTypeCount = 2 // Full and Domain
)

type mphRuleInfo struct {
	rollingHash uint32
	matchers    [mphMatchTypeCount][]uint32
}

// MphMatcherGroup is an implementation of MatcherGroup.
// It implements Rabin-Karp algorithm and minimal perfect hash table for Full and Domain matcher.
type MphMatcherGroup struct {
	rules      []string   // RuleIdx -> pattern string, index 0 reserved for failed lookup
	values     [][]uint32 // RuleIdx -> registered matcher values for the pattern (Full Matcher takes precedence)
	level0     []uint32   // RollingHash & Mask -> seed for Memhash
	level0Mask uint32     // Mask restricting RollingHash to 0 ~ len(level0)
	level1     []uint32   // Memhash<seed> & Mask -> stored index for rules
	level1Mask uint32     // Mask for restricting Memhash<seed> to 0 ~ len(level1)
	ruleInfos  *map[string]mphRuleInfo
}

func NewMphMatcherGroup() *MphMatcherGroup {
	return &MphMatcherGroup{
		rules:      []string{""},
		values:     [][]uint32{nil},
		level0:     nil,
		level0Mask: 0,
		level1:     nil,
		level1Mask: 0,
		ruleInfos:  &map[string]mphRuleInfo{}, // Only used for building, destroyed after build complete
	}
}

// AddFullMatcher implements MatcherGroupForFull.
func (g *MphMatcherGroup) AddFullMatcher(matcher FullMatcher, value uint32) {
	pattern := strings.ToLower(matcher.Pattern())
	g.addPattern(0, "", pattern, matcher.Type(), value)
}

// AddDomainMatcher implements MatcherGroupForDomain.
func (g *MphMatcherGroup) AddDomainMatcher(matcher DomainMatcher, value uint32) {
	pattern := strings.ToLower(matcher.Pattern())
	hash := g.addPattern(0, "", pattern, matcher.Type(), value) // For full domain match
	g.addPattern(hash, pattern, ".", matcher.Type(), value)     // For partial domain match
}

func (g *MphMatcherGroup) addPattern(suffixHash uint32, suffixPattern string, pattern string, matcherType Type, value uint32) uint32 {
	fullPattern := pattern + suffixPattern
	info, found := (*g.ruleInfos)[fullPattern]
	if !found {
		info = mphRuleInfo{rollingHash: RollingHash(suffixHash, pattern)}
		g.rules = append(g.rules, fullPattern)
		g.values = append(g.values, nil)
	}
	info.matchers[matcherType] = append(info.matchers[matcherType], value)
	(*g.ruleInfos)[fullPattern] = info
	return info.rollingHash
}

// Build builds a minimal perfect hash table for insert rules.
// Algorithm used: Hash, displace, and compress. See http://cmph.sourceforge.net/papers/esa09.pdf
func (g *MphMatcherGroup) Build() error {
	ruleCount := len(*g.ruleInfos)
	g.level0 = make([]uint32, nextPow2(ruleCount/4))
	g.level0Mask = uint32(len(g.level0) - 1)
	g.level1 = make([]uint32, nextPow2(ruleCount))
	g.level1Mask = uint32(len(g.level1) - 1)

	// Create buckets based on all rule's rolling hash
	buckets := make([][]uint32, len(g.level0))
	for ruleIdx := 1; ruleIdx < len(g.rules); ruleIdx++ { // Traverse rules starting from index 1 (0 reserved for failed lookup)
		ruleInfo := (*g.ruleInfos)[g.rules[ruleIdx]]
		bucketIdx := ruleInfo.rollingHash & g.level0Mask
		buckets[bucketIdx] = append(buckets[bucketIdx], uint32(ruleIdx))
		g.values[ruleIdx] = append(ruleInfo.matchers[Full], ruleInfo.matchers[Domain]...) // nolint:gocritic
	}
	g.ruleInfos = nil // Set ruleInfos nil to release memory

	// Sort buckets in descending order with respect to each bucket's size
	bucketIdxs := make([]int, len(buckets))
	for bucketIdx := range buckets {
		bucketIdxs[bucketIdx] = bucketIdx
	}
	sort.Slice(bucketIdxs, func(i, j int) bool { return len(buckets[bucketIdxs[i]]) > len(buckets[bucketIdxs[j]]) })

	// Exercise Hash, Displace, and Compress algorithm to construct minimal perfect hash table
	occupied := make([]bool, len(g.level1)) // Whether a second-level hash has been already used
	hashedBucket := make([]uint32, 0, 4)    // Second-level hashes for each rule in a specific bucket
	for _, bucketIdx := range bucketIdxs {
		bucket := buckets[bucketIdx]
		hashedBucket = hashedBucket[:0]
		seed := uint32(0)
		for len(hashedBucket) != len(bucket) {
			for _, ruleIdx := range bucket {
				memHash := MemHash(seed, g.rules[ruleIdx]) & g.level1Mask
				if occupied[memHash] { // Collision occurred with this seed
					for _, hash := range hashedBucket { // Revert all values in this hashed bucket
						occupied[hash] = false
						g.level1[hash] = 0
					}
					hashedBucket = hashedBucket[:0]
					seed++ // Try next seed
					break
				}
				occupied[memHash] = true
				g.level1[memHash] = ruleIdx // The final value in the hash table
				hashedBucket = append(hashedBucket, memHash)
			}
		}
		g.level0[bucketIdx] = seed // Displacement value for this bucket
	}
	return nil
}

// Lookup searches for input in minimal perfect hash table and returns its index. 0 indicates not found.
func (g *MphMatcherGroup) Lookup(rollingHash uint32, input string) uint32 {
	i0 := rollingHash & g.level0Mask
	seed := g.level0[i0]
	i1 := MemHash(seed, input) & g.level1Mask
	if n := g.level1[i1]; g.rules[n] == input {
		return n
	}
	return 0
}

// Match implements MatcherGroup.Match.
func (g *MphMatcherGroup) Match(input string) []uint32 {
	matches := make([][]uint32, 0, 5)
	hash := uint32(0)
	for i := len(input) - 1; i >= 0; i-- {
		hash = hash*PrimeRK + uint32(input[i])
		if input[i] == '.' {
			if mphIdx := g.Lookup(hash, input[i:]); mphIdx != 0 {
				matches = append(matches, g.values[mphIdx])
			}
		}
	}
	if mphIdx := g.Lookup(hash, input); mphIdx != 0 {
		matches = append(matches, g.values[mphIdx])
	}
	return CompositeMatchesReverse(matches)
}

// MatchAny implements MatcherGroup.MatchAny.
func (g *MphMatcherGroup) MatchAny(input string) bool {
	hash := uint32(0)
	for i := len(input) - 1; i >= 0; i-- {
		hash = hash*PrimeRK + uint32(input[i])
		if input[i] == '.' {
			if g.Lookup(hash, input[i:]) != 0 {
				return true
			}
		}
	}
	return g.Lookup(hash, input) != 0
}

func nextPow2(v int) int {
	if v <= 1 {
		return 1
	}
	const MaxUInt = ^uint(0)
	n := (MaxUInt >> bits.LeadingZeros(uint(v))) + 1
	return int(n)
}

//go:noescape
//go:linkname strhash runtime.strhash
func strhash(p unsafe.Pointer, h uintptr) uintptr

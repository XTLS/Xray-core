package conf

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// FingerprintWeights is an explicit set of browser fingerprints and positive
// relative weights. Callers must not modify the map concurrently with its methods.
// This type does not change the existing single-fingerprint or random modes.
type FingerprintWeights map[string]uint64

type weightedFingerprint struct {
	name   string
	weight uint64
}

type fingerprintPolicy struct {
	entries []weightedFingerprint
	total   uint64
	key     string
}

// Validate checks the entire policy without selecting or caching a fingerprint.
// Transport-specific compatibility checks must also run before Resolve.
func (w FingerprintWeights) Validate() error {
	_, err := w.policy()
	return err
}

// Resolve selects once per normalized policy per process. Equivalent policies
// share a result even across separately built configurations. Restarting the
// process permits a new choice; reconnecting does not. Errors are not cached.
func (w FingerprintWeights) Resolve() (string, error) {
	return processFingerprints.resolve(w)
}

func (w FingerprintWeights) policy() (*fingerprintPolicy, error) {
	if len(w) == 0 {
		return nil, fmt.Errorf("fingerprintWeights must not be empty")
	}
	p := &fingerprintPolicy{}
	seen := make(map[string]bool, len(w))
	var divisor uint64
	for name, weight := range w {
		name = strings.ToLower(name)
		if name == "" || seen[name] {
			return nil, fmt.Errorf("fingerprintWeights: empty or duplicate fingerprint %q", name)
		}
		seen[name] = true
		fp := tls.GetFingerprint(name)
		if name == "random" || fp == nil || fp.Client == utls.HelloGolang.Client || strings.HasPrefix(fp.Client, utls.HelloRandomized.Client) {
			return nil, fmt.Errorf("fingerprintWeights: unsupported browser fingerprint %q", name)
		}
		if weight == 0 {
			return nil, fmt.Errorf("fingerprintWeights: weight for %q must be positive", name)
		}
		if weight > math.MaxUint64-p.total {
			return nil, fmt.Errorf("fingerprintWeights: total weight overflows uint64")
		}
		p.total += weight
		p.entries = append(p.entries, weightedFingerprint{name: name, weight: weight})
		divisor = fingerprintGCD(divisor, weight)
	}
	sort.Slice(p.entries, func(i, j int) bool { return p.entries[i].name < p.entries[j].name })
	p.total /= divisor
	var key strings.Builder
	for i := range p.entries {
		entry := &p.entries[i]
		entry.weight /= divisor
		key.WriteString(strconv.Quote(entry.name))
		key.WriteByte(':')
		key.WriteString(strconv.FormatUint(entry.weight, 10))
		key.WriteByte(';')
	}
	p.key = key.String()
	return p, nil
}

func fingerprintGCD(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// pick maps an unbiased integer in [0, total) to its weighted interval.
func (p *fingerprintPolicy) pick(n uint64) string {
	for _, entry := range p.entries {
		if n < entry.weight {
			return entry.name
		}
		n -= entry.weight
	}
	panic("fingerprint selection outside policy range")
}

type fingerprintResolver struct {
	mu      sync.Mutex
	choices map[string]string
	draw    func(uint64) (uint64, error)
}

var processFingerprints = fingerprintResolver{draw: drawFingerprint}

func drawFingerprint(total uint64) (uint64, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(total))
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}

func (r *fingerprintResolver) resolve(w FingerprintWeights) (string, error) {
	p, err := w.policy()
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if name, ok := r.choices[p.key]; ok {
		return name, nil
	}
	var n uint64
	if len(p.entries) > 1 {
		n, err = r.draw(p.total)
		if err != nil {
			return "", fmt.Errorf("fingerprintWeights: selecting fingerprint: %w", err)
		}
	}
	name := p.pick(n)
	if r.choices == nil {
		r.choices = make(map[string]string)
	}
	r.choices[p.key] = name
	return name, nil
}

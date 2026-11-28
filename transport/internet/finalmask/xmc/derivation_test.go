package xmc

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
)

// fermatFactorsInOneStep reports whether the public modulus alone discloses the
// private key. One iteration of Fermat's method yields a square exactly when N
// is the product of two primes with a small gap, which is what happens when p
// and q are derived from the same stream (p == q repaired by stepping q to the
// next prime).
func fermatFactorsInOneStep(n *big.Int) bool {
	a := new(big.Int).Sqrt(n)
	a.Add(a, big.NewInt(1))
	b2 := new(big.Int).Sub(new(big.Int).Mul(a, a), n)
	if b2.Sign() < 0 {
		return false
	}
	b := new(big.Int).Sqrt(b2)
	return new(big.Int).Mul(b, b).Cmp(b2) == 0
}

func requireUsableKey(t *testing.T, password string) *rsa.PrivateKey {
	t.Helper()
	key, err := DeriveRSAKey(password)
	if err != nil {
		t.Fatalf("DeriveRSAKey(%q): %v", password, err)
	}
	if key.N.BitLen() != 1024 {
		t.Fatalf("%q: N is %d bits, want 1024", password, key.N.BitLen())
	}
	if key.E != 65537 {
		t.Fatalf("%q: E is %d, want 65537", password, key.E)
	}
	if len(key.Primes) != 2 {
		t.Fatalf("%q: got %d primes, want 2", password, len(key.Primes))
	}
	if key.Primes[0].Cmp(key.Primes[1]) == 0 {
		t.Fatalf("%q (%d bytes): p == q", password, len(password))
	}
	if fermatFactorsInOneStep(key.N) {
		t.Fatalf("%q (%d bytes): N factors at the first Fermat step, p and q are neighbouring primes", password, len(password))
	}
	if got := new(big.Int).Mul(key.Primes[0], key.Primes[1]); got.Cmp(key.N) != 0 {
		t.Fatalf("%q: p*q != N", password)
	}
	return key
}

// TestNewSHA256StreamOwnsItsSeed is the direct regression test for the aliasing
// defect: the stream hashes its seed on every refill, so it must not retain a
// slice whose backing array a caller may still append to.
func TestNewSHA256StreamOwnsItsSeed(t *testing.T) {
	password := []byte(strings.Repeat("k", 100))
	// Mimic []byte(password) handing out a buffer with spare capacity, which is
	// what made the two DeriveRSAKey appends overlap in the first place.
	shared := make([]byte, len(password), len(password)+2*32)
	copy(shared, password)

	pStream := newSHA256Stream(append(shared, []byte("-p-prime")...))
	qStream := newSHA256Stream(append(shared, []byte("-q-prime")...))

	if bytes.HasSuffix(pStream.seed, []byte("-q-prime")) {
		t.Fatalf("p stream seed was rewritten by the q stream's append: %q", pStream.seed)
	}
	if !bytes.HasPrefix(pStream.seed, password) || !bytes.HasSuffix(pStream.seed, []byte("-p-prime")) {
		t.Fatalf("p stream seed = %q, want <password>-p-prime", pStream.seed)
	}
	if !bytes.HasPrefix(qStream.seed, password) || !bytes.HasSuffix(qStream.seed, []byte("-q-prime")) {
		t.Fatalf("q stream seed = %q, want <password>-q-prime", qStream.seed)
	}
	if &pStream.seed[0] == &qStream.seed[0] {
		t.Fatal("both streams share one backing array")
	}

	// Whatever happens to the caller's buffer afterwards, the streams are fixed.
	for i := range shared {
		shared[i] = 'z'
	}
	if !bytes.HasPrefix(pStream.seed, password) || !bytes.HasPrefix(qStream.seed, password) {
		t.Fatal("stream seed follows the caller's buffer after construction")
	}
}

func referenceStreamBytes(seed string, blocks int) []byte {
	out := make([]byte, 0, blocks*sha256.Size)
	for i := 0; i < blocks; i++ {
		h := sha256.New()
		h.Write([]byte(seed))
		fmt.Fprintf(h, "-%d", i)
		out = append(out, h.Sum(nil)...)
	}
	return out
}

func TestSHA256StreamMatchesReference(t *testing.T) {
	for _, seed := range []string{
		"",
		"password",
		strings.Repeat("a", 113),
		"00000000-0000-0000-0000-000000000000-p-prime",
	} {
		got := make([]byte, 3*sha256.Size)
		if _, err := newSHA256Stream([]byte(seed)).Read(got); err != nil {
			t.Fatalf("seed %q: %v", seed, err)
		}
		want := referenceStreamBytes(seed, 3)
		if !bytes.Equal(got, want) {
			t.Fatalf("seed %q: keystream mismatch", seed)
		}
	}
}

// TestDeriveRSAKeyAllPasswordLengths sweeps every password length the login
// accepts. Lengths whose allocation rounded up left spare capacity for the
// "-p-prime"/"-q-prime" appends (33-40, 49-56, 65-72, 81-88, 97-104, 113 at the
// time of the fix), but the whole range is checked so a change in allocator size
// classes or escape analysis cannot reintroduce the defect unnoticed.
func TestDeriveRSAKeyAllPasswordLengths(t *testing.T) {
	for n := 1; n <= MaxLegacyPasswordLength; n++ {
		n := n
		t.Run(fmt.Sprintf("len-%03d", n), func(t *testing.T) {
			requireUsableKey(t, strings.Repeat("a", n))
		})
	}
}

// TestDeriveRSAKeyBoundaryLengths pins the lengths next to the capacity
// boundaries where the pre-fix code switched between aliasing and reallocating.
func TestDeriveRSAKeyBoundaryLengths(t *testing.T) {
	for _, n := range []int{15, 16, 17, 23, 24, 25, 31, 32, 33, 39, 40, 41, 47, 48, 49, 55, 56, 57, 63, 64, 65, 71, 72, 73, 79, 80, 81, 87, 88, 89, 95, 96, 97, 103, 104, 105, 111, 112, 113} {
		n := n
		t.Run(fmt.Sprintf("len-%03d", n), func(t *testing.T) {
			requireUsableKey(t, strings.Repeat("b", n))
		})
	}
}

// TestDeriveRSAKeyNonASCIIPasswords covers multi-byte passwords: the affected
// ranges are byte lengths, so a 12-character CJK password is a 36-byte one.
func TestDeriveRSAKeyNonASCIIPasswords(t *testing.T) {
	passwords := map[string]string{
		"cjk-33-bytes":     strings.Repeat("密", 11),
		"cjk-36-bytes":     strings.Repeat("密", 12),
		"emoji-36-bytes":   strings.Repeat("🔒", 9),
		"mixed-utf8":       "密码-Password-密码-0123456789-密码-0123",
		"embedded-nul":     "abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"all-high-bytes":   strings.Repeat("\xff", 40),
		"surrogate-ish-41": strings.Repeat("é", 20) + "x",
	}
	for name, password := range passwords {
		password := password
		t.Run(name, func(t *testing.T) {
			t.Logf("password is %d bytes", len(password))
			requireUsableKey(t, password)
		})
	}
}

// TestDeriveRSAKeyExtremeInputs keeps the derivation total over sizes far
// outside what the login accepts: it is called from configuration building, so
// it must not panic or depend on a particular capacity.
func TestDeriveRSAKeyExtremeInputs(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"one-byte":       "x",
		"max-accepted":   strings.Repeat("m", MaxLegacyPasswordLength),
		"just-over-max":  strings.Repeat("m", MaxLegacyPasswordLength+1),
		"four-kibibytes": strings.Repeat("m", 4096),
	}
	for name, password := range cases {
		password := password
		t.Run(name, func(t *testing.T) {
			requireUsableKey(t, password)
		})
	}
}

// TestDeriveRSAKeyDeterministic checks that both ends of a connection derive the
// same key, including when several goroutines build configurations at once.
func TestDeriveRSAKeyDeterministic(t *testing.T) {
	const password = "00000000-0000-0000-0000-000000000000"
	want := requireUsableKey(t, password).N

	const workers = 8
	results := make([]*big.Int, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key, err := DeriveRSAKey(password)
			if err != nil {
				panic(err)
			}
			results[i] = key.N
		}(i)
	}
	wg.Wait()

	for i, n := range results {
		if n.Cmp(want) != 0 {
			t.Fatalf("worker %d derived a different modulus", i)
		}
	}
}

// TestDeriveRSAKeyKnownAnswers pins the derivation. The key is a wire-level
// shared secret: changing it for an unaffected password would break every
// existing deployment, so the digests below must only ever change on purpose.
// The 8-, 18- and 32-byte entries are byte-identical to what the aliasing code
// derived, which is the compatibility promise of the fix; the 36- and 113-byte
// entries were the ones whose key had to change.
func TestDeriveRSAKeyKnownAnswers(t *testing.T) {
	cases := []struct {
		password string
		nDigest  string
	}{
		{"password", "cf683eb5c302ca70"},
		{"padding-regression", "b9e1f7f9b936fb8d"},
		{strings.Repeat("a", 32), "6692488374c0e7aa"},
		{"00000000-0000-0000-0000-000000000000", "6d971fd64a5c0981"},
		{strings.Repeat("m", MaxLegacyPasswordLength), "45b0e2f0dd483585"},
	}
	for _, c := range cases {
		key := requireUsableKey(t, c.password)
		digest := sha256.Sum256(key.N.Bytes())
		got := hex.EncodeToString(digest[:8])
		if got != c.nDigest {
			t.Fatalf("%d-byte password: N digest %s, want %s (wire-compatibility break)", len(c.password), got, c.nDigest)
		}
	}
}

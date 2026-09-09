package xmc

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type sha256Stream struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func newSHA256Stream(seed []byte) *sha256Stream {
	return &sha256Stream{
		seed: seed,
	}
}

func (s *sha256Stream) Read(p []byte) (n int, err error) {
	for len(p) > len(s.buf) {
		h := sha256.New()
		h.Write(s.seed)
		h.Write([]byte(fmt.Sprintf("-%d", s.counter)))
		s.counter++
		s.buf = append(s.buf, h.Sum(nil)...)
	}
	n = copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func derivePrime(stream *sha256Stream) *big.Int {
	pBytes := make([]byte, 64) // 512 bits
	_, _ = stream.Read(pBytes)
	pBytes[0] |= 0xc0  // ensure it is big enough so p*q is 1024 bits
	pBytes[63] |= 0x01 // ensure odd

	p := new(big.Int).SetBytes(pBytes)
	for {
		if p.ProbablyPrime(20) {
			pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
			e := big.NewInt(65537)
			gcd := new(big.Int).GCD(nil, nil, pMinus1, e)
			if gcd.Cmp(big.NewInt(1)) == 0 {
				return p
			}
		}
		p.Add(p, big.NewInt(2))
	}
}

// DeriveRSAKey derives a 1024-bit RSA private key from a password.
func DeriveRSAKey(password string) (*rsa.PrivateKey, error) {
	seed := []byte(password)

	pStream := newSHA256Stream(append(seed, []byte("-p-prime")...))
	qStream := newSHA256Stream(append(seed, []byte("-q-prime")...))

	p := derivePrime(pStream)
	q := derivePrime(qStream)

	// ensure p != q (if they are, let's search q further)
	for p.Cmp(q) == 0 {
		q.Add(q, big.NewInt(2))
		for {
			if q.ProbablyPrime(20) {
				qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
				e := big.NewInt(65537)
				gcd := new(big.Int).GCD(nil, nil, qMinus1, e)
				if gcd.Cmp(big.NewInt(1)) == 0 {
					break
				}
			}
			q.Add(q, big.NewInt(2))
		}
	}

	n := new(big.Int).Mul(p, q)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	totient := new(big.Int).Mul(pMinus1, qMinus1)

	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, totient)
	if d == nil {
		return nil, fmt.Errorf("failed to compute mod inverse")
	}

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: 65537,
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	priv.Precompute()

	return priv, nil
}

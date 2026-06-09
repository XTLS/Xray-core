package minecraft

// Copied from https://github.com/Tnze/go-mc/blob/539b4a3a7f030332eb58b8a946116ae7907630d2/net/CFB8/cfb8.go

import (
	"crypto/cipher"
	"crypto/subtle"
	"unsafe"
)

type cfb8 struct {
	c         cipher.Block
	blockSize int
	ivPos     int
	iv        []byte
	de        bool
}

func newCFB8Decrypt(c cipher.Block, iv []byte) *cfb8 {
	return newCFB8(c, iv, true)
}

func newCFB8Encrypt(c cipher.Block, iv []byte) *cfb8 {
	return newCFB8(c, iv, false)
}

func newCFB8(c cipher.Block, iv []byte, de bool) *cfb8 {
	cp := make([]byte, len(iv)*3)
	copy(cp, iv)
	return &cfb8{
		c:         c,
		blockSize: c.BlockSize(),
		iv:        cp,
		de:        de,
	}
}

func (cf *cfb8) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("cfb8: output smaller than input")
	}

	// If dst and src does not overlap in first block size,
	// and the length of src is greater than 2*blockSize,
	// we can use an optimized implementation.
	if len(src) > cf.blockSize<<1 &&
		(uintptr(unsafe.Pointer(&dst[0]))+uintptr(cf.blockSize) <= uintptr(unsafe.Pointer(&src[0])) ||
			uintptr(unsafe.Pointer(&src[0]))+uintptr(len(src)) <= uintptr(unsafe.Pointer(&dst[0]))) {
		// encrypt/decrypt first blockSize bytes
		// After this, the IV will come to the same as
		// the last blockSize of ciphertext, so
		// we can reuse them without copy.
		cf.xorKeyStream(dst, src[:cf.blockSize])
		var ciphertext []byte
		if cf.de {
			ciphertext = src
		} else {
			ciphertext = dst
		}
		dst = dst[cf.blockSize:]
		src = src[cf.blockSize:]
		iv := cf.iv
		_ = iv[0] // bounds check hint to compiler; see golang.org/issue/14808
		var (
			i   int
			val byte
		)
		dst = dst[:len(src)]
		if cf.de && // and requires to be non-overlapping at all
			uintptr(unsafe.Pointer(&dst[0])) <= uintptr(unsafe.Pointer(&src[len(src)-1])) &&
			uintptr(unsafe.Pointer(&src[0])) <= uintptr(unsafe.Pointer(&dst[len(dst)-1])) {
			for i = 0; i < len(src)-cf.blockSize; i += 1 {
				cf.c.Encrypt(dst[i:], ciphertext[i:])
			}
			subtle.XORBytes(dst, src[:i], dst)
			for ; i < len(src); i += 1 {
				cf.c.Encrypt(iv, ciphertext[i:])
				dst[i] = src[i] ^ iv[0]
			}
		} else {
			_ = ciphertext[len(src)]
			for i, val = range src {
				cf.c.Encrypt(iv, ciphertext[i:])
				dst[i] = val ^ iv[0]
			}
			// for-range does not increase i in the last loop,
			// compared to the classic for clause
			i += 1
		}
		// copy the current IV for next operation
		copy(iv, ciphertext[i:i+cf.blockSize])
		cf.ivPos = 0
		return
	}

	cf.xorKeyStream(dst, src)
}

func (cf *cfb8) xorKeyStream(dst, src []byte) {
	dst = dst[:len(src)] // remove bounds check in loop
	for i, val := range src {
		posPlusBlockSize := cf.ivPos + cf.blockSize
		// fast mod; 2*blockSize must be a non-negative integer power of 2
		tempPos := posPlusBlockSize & (cf.blockSize<<1 - 1)
		// reuse space to store encrypted block
		cf.c.Encrypt(cf.iv[tempPos:], cf.iv[cf.ivPos:])
		// Only the first byte of the encrypted block is used
		// for encryption/decryption, other bytes are ignored.
		val ^= cf.iv[tempPos]

		if cf.ivPos == cf.blockSize<<1 {
			// bound reached; move to next round for next operation
			// copy next block to the start of the ring buffer
			copy(cf.iv, cf.iv[cf.ivPos+1:])
			// insert the encrypted byte to the end of IV
			if cf.de {
				cf.iv[cf.blockSize-1] = src[i]
			} else {
				cf.iv[cf.blockSize-1] = val
			}
			cf.ivPos = 0
		} else {
			// insert the encrypted byte to the end of IV
			if cf.de {
				cf.iv[posPlusBlockSize] = src[i]
			} else {
				cf.iv[posPlusBlockSize] = val
			}
			// move to next block
			cf.ivPos += 1
		}

		dst[i] = val
	}
}

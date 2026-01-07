package router

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/xtls/xray-core/common/strmatcher"
)

func SerializeGeoSiteList(sites []*GeoSite, w io.Writer) error {
	// data buffers
	var buffers [][]byte
	var countryCodes []string

	for _, site := range sites {
		if site == nil {
			continue
		}
		var buf bytes.Buffer
		if err := SerializeDomainMatcher(site.Domain, &buf); err != nil {
			return err
		}
		buffers = append(buffers, buf.Bytes())
		countryCodes = append(countryCodes, site.CountryCode)
	}

	// header, count ,4
	if err := binary.Write(w, binary.LittleEndian, uint32(len(buffers))); err != nil {
		return err
	}

	currentOffset := uint64(4) // header

	// calc index size first
	var indexSize uint64
	for _, code := range countryCodes {
		indexSize += 1 + uint64(len(code)) + 16
	}
	currentOffset += indexSize

	// write entry
	for i, code := range countryCodes {
		codeBytes := []byte(code)
		if len(codeBytes) > 255 {
			return errors.New("country code too long")
		}

		// len
		if _, err := w.Write([]byte{byte(len(codeBytes))}); err != nil {
			return err
		}
		// code
		if _, err := w.Write(codeBytes); err != nil {
			return err
		}

		size := uint64(len(buffers[i]))

		// offset
		if err := binary.Write(w, binary.LittleEndian, currentOffset); err != nil {
			return err
		}
		// size
		if err := binary.Write(w, binary.LittleEndian, size); err != nil {
			return err
		}

		currentOffset += size
	}

	// data
	for _, buf := range buffers {
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}

	return nil
}

func LoadGeoSiteMatcher(data []byte, countryCode string) (*strmatcher.MphMatcherGroup, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid data length")
	}

	count := binary.LittleEndian.Uint32(data[0:4])

	offset := 4
	targetBytes := []byte(countryCode)

	for range count {
		if offset >= len(data) {
			return nil, errors.New("index truncated")
		}

		codeLen := int(data[offset])
		offset++

		if offset+codeLen > len(data) {
			return nil, errors.New("index code truncated")
		}

		code := data[offset : offset+codeLen]
		offset += codeLen

		if offset+16 > len(data) {
			return nil, errors.New("index meta truncated")
		}

		dataOffset := binary.LittleEndian.Uint64(data[offset : offset+8])
		dataSize := binary.LittleEndian.Uint64(data[offset+8 : offset+16])
		offset += 16

		// match?
		if bytes.Equal(code, targetBytes) {
			if dataOffset+dataSize > uint64(len(data)) {
				return nil, errors.New("data truncated")
			}
			return NewDomainMatcherFromBuffer(data[dataOffset : dataOffset+dataSize])
		}
	}

	return nil, errors.New("country code not found")
}

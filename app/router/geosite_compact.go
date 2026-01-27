package router

import (
	"bufio"
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

func LoadGeoSiteMatcher(r io.Reader, countryCode string) (*strmatcher.MphMatcherGroup, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	var count uint32
	if err := binary.Read(br, binary.LittleEndian, &count); err != nil {
		return nil, err
	}

	targetBytes := []byte(countryCode)
	var dataOffset, dataSize uint64
	var found bool

	bytesRead := uint64(4)

	for i := uint32(0); i < count; i++ {
		codeLen, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		bytesRead++

		code := make([]byte, int(codeLen))
		if _, err := io.ReadFull(br, code); err != nil {
			return nil, err
		}
		bytesRead += uint64(codeLen)

		var offsetValue, sizeValue uint64
		if err := binary.Read(br, binary.LittleEndian, &offsetValue); err != nil {
			return nil, err
		}
		bytesRead += 8
		if err := binary.Read(br, binary.LittleEndian, &sizeValue); err != nil {
			return nil, err
		}
		bytesRead += 8

		if bytes.Equal(code, targetBytes) {
			dataOffset = offsetValue
			dataSize = sizeValue
			found = true
		}
	}

	if !found {
		return nil, errors.New("country code not found")
	}

	if dataOffset < bytesRead {
		return nil, errors.New("invalid data offset")
	}

	toSkip := dataOffset - bytesRead
	if toSkip > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(toSkip)); err != nil {
			return nil, err
		}
	}

	data := make([]byte, dataSize)
	if _, err := io.ReadFull(br, data); err != nil {
		return nil, err
	}

	return NewDomainMatcherFromBuffer(data)
}

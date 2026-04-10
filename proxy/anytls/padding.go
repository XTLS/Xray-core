package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const CheckMark = -1

var defaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

type paddingScheme struct {
	rawScheme []byte
	scheme    map[string]string
	stop      uint32
	md5       string
}

func newPaddingScheme(rawScheme []byte) *paddingScheme {
	p := &paddingScheme{
		rawScheme: rawScheme,
		md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}

	scheme := make(map[string]string)
	lines := strings.Split(string(rawScheme), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			scheme[parts[0]] = parts[1]
		}
	}

	if len(scheme) == 0 {
		return nil
	}

	if stop, err := strconv.Atoi(scheme["stop"]); err == nil {
		p.stop = uint32(stop)
	} else {
		return nil
	}

	p.scheme = scheme
	return p
}

func getDefaultPaddingScheme() *paddingScheme {
	return newPaddingScheme(defaultPaddingScheme)
}

func parsePaddingScheme(schemeStr string) (*paddingScheme, error) {
	if schemeStr == "" {
		return nil, nil
	}
	return newPaddingScheme([]byte(schemeStr)), nil
}

func (p *paddingScheme) GenerateRecordPayloadSizes(pkt uint32) []int {
	if p == nil {
		return nil
	}

	pktSizes := []int{}
	key := strconv.Itoa(int(pkt))
	s, ok := p.scheme[key]
	if !ok {
		return pktSizes
	}

	sRanges := strings.Split(s, ",")
	for _, sRange := range sRanges {
		sRange = strings.TrimSpace(sRange)

		if sRange == "c" {
			pktSizes = append(pktSizes, CheckMark)
			continue
		}

		sRangeMinMax := strings.Split(sRange, "-")
		if len(sRangeMinMax) != 2 {
			continue
		}

		_min, err := strconv.ParseInt(sRangeMinMax[0], 10, 64)
		if err != nil {
			continue
		}
		_max, err := strconv.ParseInt(sRangeMinMax[1], 10, 64)
		if err != nil {
			continue
		}

		if _min > _max {
			_min, _max = _max, _min
		}

		if _min <= 0 || _max <= 0 {
			continue
		}

		if _min == _max {
			pktSizes = append(pktSizes, int(_min))
		} else {
			i, _ := rand.Int(rand.Reader, big.NewInt(_max-_min))
			pktSizes = append(pktSizes, int(i.Int64()+_min))
		}
	}

	return pktSizes
}

func getPadding0Size(scheme *paddingScheme) uint16 {
	if scheme == nil {
		return 30
	}

	sizes := scheme.GenerateRecordPayloadSizes(0)
	if len(sizes) > 0 && sizes[0] != CheckMark {
		return uint16(sizes[0])
	}

	return 30
}

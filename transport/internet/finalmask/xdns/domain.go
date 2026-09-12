package xdns

import (
	"encoding/base32"
	"errors"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

func Lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func ToUpper(b []byte) {
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
}

func ToLower(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c - 'A' + 'a'
		}
	}
}

func NewTable() ([256]int, [256]int) {
	var t, t_ [256]int
	for i := range t {
		t[i] = base32Encoding.DecodedLen(i)
	}
	for i := range t_ {
		t_[i] = base32Encoding.EncodedLen(i)
	}
	return t, t_
}

const (
	TypeA     uint16 = 1
	TypeCNAME uint16 = 5
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
)

var (
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	table, table_  = NewTable()
	TypeMap        = map[uint16]byte{
		TypeA:     0,
		TypeCNAME: 1,
		TypeTXT:   2,
		TypeAAAA:  3,
	}
	TypeMap_ = map[byte]uint16{
		0: TypeA,
		1: TypeCNAME,
		2: TypeTXT,
		3: TypeAAAA,
	}
)

type Domain struct {
	name       dnsmessage.Name
	lenLimit   int
	labelLimit int
	types      []uint16
	edns0      uint16

	cap    int
	lenMax int
}

func NewDomain(domain string, lenLimit int, labelLimit int, types []uint16, edns0 uint16) (*Domain, error) {
	if strings.Contains(domain, "..") {
		return nil, errors.New("invalid domain")
	}
	if lenLimit < 0 || lenLimit > 255 {
		return nil, errors.New("lenLimit < 0 || lenLimit > 255")
	}
	if labelLimit < 0 || labelLimit > 63 {
		return nil, errors.New("labelLimit < 0 || labelLimit > 63")
	}
	if len(types) == 0 {
		return nil, errors.New("empty types")
	}
	for i := range types {
		switch types[i] {
		case uint16(dnsmessage.TypeA), uint16(dnsmessage.TypeCNAME), uint16(dnsmessage.TypeTXT), uint16(dnsmessage.TypeAAAA):
		default:
			return nil, errors.New("unknown types")
		}
	}
	if edns0 != 0 && (edns0 < 512 || edns0 > 4096) {
		return nil, errors.New("edns0 != 0 && (edns0 < 512 || edns0 > 4096)")
	}

	ascii, err := idna.ToASCII(domain)
	if err != nil {
		return nil, err
	}
	ascii = strings.Trim(ascii, ".")

	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		return nil, err
	}

	if lenLimit < int(name.Length)+1 {
		return nil, errors.New("lenLimit < int(name.Length)+1")
	}
	n := (lenLimit - int(name.Length) - 1) / (labelLimit + 1)
	left := (lenLimit - int(name.Length) - 1) % (labelLimit + 1)
	total := n * labelLimit
	if left > 1 {
		total += left - 1
	}
	cap := table[total]
	if cap < 16 {
		return nil, errors.New("cap < 16")
	}
	total = table_[cap]
	lenMax := int(name.Length) + 1 + total + total/labelLimit
	if total%labelLimit > 0 {
		lenMax += 1
	}
	return &Domain{
		name:       name,
		lenLimit:   lenLimit,
		labelLimit: labelLimit,
		types:      types,
		edns0:      edns0,

		cap:    cap,
		lenMax: lenMax,
	}, nil
}

func (d *Domain) IsDomain(name dnsmessage.Name) bool {
	if d.name.Length >= name.Length {
		return false
	}
	i := d.name.Length
	j := name.Length
	for i > 0 {
		i--
		j--
		if Lower(d.name.Data[i]) != Lower(name.Data[j]) {
			return false
		}
	}
	return true
}

func (d *Domain) HasType(qtype uint16) bool {
	for i := range d.types {
		if d.types[i] == qtype {
			return true
		}
	}
	return false
}

func (d *Domain) Encode(data []byte) dnsmessage.Name {
	var name dnsmessage.Name
	var encoded [255]byte
	base32Encoding.Encode(encoded[:], data)
	ToLower(encoded[:table_[len(data)]])
	b1 := name.Data[:0]
	b2 := encoded[:table_[len(data)]]
	for len(b2) > 0 {
		size := min(len(b2), d.labelLimit)
		b1 = append(b1, b2[:size]...)
		b1 = append(b1, '.')
		b2 = b2[size:]
	}
	b1 = append(b1, d.name.Data[:d.name.Length]...)
	if len(b1) > 254 {
		panic("len(b1) > 254")
	}
	name.Length = byte(len(b1))
	return name
}

func (d *Domain) Decode(decoded *[255]byte, name dnsmessage.Name) (int, error) {
	if !d.IsDomain(name) {
		return 0, errors.New("incorrect domain")
	}
	var encoded [255]byte
	b1 := encoded[:0]
	b2 := name.Data[:name.Length-d.name.Length]
	for i := range b2 {
		if b2[i] != '.' {
			b1 = append(b1, b2[i])
		}
	}
	ToUpper(b1)
	return base32Encoding.Decode(decoded[:], b1)
}

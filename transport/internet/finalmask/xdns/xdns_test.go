package xdns

import (
	"bytes"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/xtls/xray-core/common"
	"golang.org/x/net/dns/dnsmessage"
)

func TestXxx(t *testing.T) {
	m1 := dnsmessage.Message{
		Questions: []dnsmessage.Question{
			{
				Name: dnsmessage.MustNewName("a.example.com."),
			},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:   dnsmessage.MustNewName("a.example.com."),
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					TTL:    60,
					Length: 16,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:   dnsmessage.MustNewName("."),
					Type:   dnsmessage.TypeOPT,
					Class:  255,
					TTL:    0,
					Length: 16,
				},
				Body: &dnsmessage.OPTResource{},
			},
		},
	}
	p1, e1 := m1.Pack()
	if e1 != nil {
		t.Fatal(e1)
	}
	if !bytes.Equal(p1, []byte{
		0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1,
		1, 97, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0,
		0, 0,
		0, 0,
		192, 12,
		0, 1,
		0, 1,
		0, 0, 0, 60,
		0, 4,
		127, 0, 0, 1,
		0,
		0, 41,
		0, 255,
		0, 0, 0, 0,
		0, 0,
	}) {
		t.Fatal("!bytes.Equal")
	}

	domain, _ := NewDomain("a.example.com", 200, 1, []uint16{1}, 0)
	fmt.Println(domain.cap, domain.capFrags, domain.lenMax)
	lenMax := domain.lenMax
	data := make([]byte, domain.cap+11)
	msg := dnsmessage.Message{}
	msg.Unpack(p1)
	for range 3 {
		msg.Answers = nil
		msg.Authorities = nil
		msg.Additionals = nil
		n := mrand.Intn(255)
		for range n {
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("a.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			})
		}
		if len(common.Must2(msg.Pack())) != 12+15+2+2+n*(2+2+2+4+2+4) {
			t.Fatal("fatal a")
		}
	}
	for range 3 {
		msg.Answers = nil
		msg.Authorities = nil
		msg.Additionals = nil
		n := mrand.Intn(255)
		for range n {
			common.Must2(rand.Read(data))
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("a.example.com."),
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.CNAMEResource{
					CNAME: domain.Encode(data),
				},
			})
		}
		if len(common.Must2(msg.Pack())) > 12+15+2+2+n*(2+2+2+4+2+lenMax) {
			t.Fatal("fatal cname")
		}
	}
	for range 3 {
		msg.Answers = nil
		msg.Authorities = nil
		msg.Additionals = nil
		n := (mrand.Intn(2048) + 1024) % 2048
		a := n / 255
		b := n % 255
		c := 0
		var d [255]byte
		var s []string
		for range a {
			s = append(s, string(d[:]))
		}
		if b > 0 {
			c = 1
			s = append(s, string(d[:b]))
		}
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("a.example.com."),
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			Body: &dnsmessage.TXTResource{TXT: s},
		})
		if len(common.Must2(msg.Pack())) != 12+15+2+2+(2+2+2+4+2+n+n/255+c) {
			t.Fatal("fatal txt")
		}
	}
	for range 3 {
		msg.Answers = nil
		msg.Authorities = nil
		msg.Additionals = nil
		n := mrand.Intn(255)
		for range n {
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("a.example.com."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte{}},
			})
		}
		if len(common.Must2(msg.Pack())) != 12+15+2+2+n*(2+2+2+4+2+16) {
			t.Fatal("fatal aaaa")
		}
	}
}

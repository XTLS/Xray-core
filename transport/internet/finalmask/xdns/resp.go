package xdns

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/dns/dnsmessage"
)

type Resp struct {
	msg     dnsmessage.Message
	domain  *Domain
	addr    net.Addr
	edns0   uint16
	SendMsg func(dnsmessage.Message, net.Addr)

	cap      int
	deadline time.Time
}

func NewResp(msg dnsmessage.Message, domain *Domain, addr net.Addr, edns0 uint16, SendMsg func(dnsmessage.Message, net.Addr)) *Resp {
	errors.LogDebug(context.Background(), addr, " edns0 ", edns0)

	if msg.Header.Response {
		return &Resp{
			msg:    msg,
			domain: domain,
		}
	}

	size := min(max(int(edns0), 512), max(int(domain.edns0), 512))

	left := size - 12 - int(msg.Questions[0].Name.Length) - 1 - 2 - 2
	if edns0 > 0 {
		left -= 1 + 2 + 2 + 4 + 2 + 0
	}
	cap := 0
	switch msg.Questions[0].Type {
	case dnsmessage.TypeA:
		single := 2 + 2 + 2 + 4 + 2 + 4
		n := left / single
		if n > 255 {
			n = 255
		}
		cap = 4*n - n - 3
	case dnsmessage.TypeCNAME:
		single := 2 + 2 + 2 + 4 + 2 + domain.lenMax
		n := left / single
		if n > 255 {
			n = 255
		}
		cap = domain.cap*n - n - 3
	case dnsmessage.TypeTXT:
		left -= 2 + 2 + 2 + 4 + 2
		single := 1 + 255
		n := left / single
		m := left % single
		cap = 255*n - n
		if m > 1 {
			cap += m - 1
		}
	case dnsmessage.TypeAAAA:
		single := 2 + 2 + 2 + 4 + 2 + 16
		n := left / single
		if n > 255 {
			n = 255
		}
		cap = 16*n - n - 3
	}
	if cap < 11+1 {
		return nil
	}

	return &Resp{
		msg:     msg,
		domain:  domain,
		addr:    addr,
		edns0:   edns0,
		SendMsg: SendMsg,

		cap:      cap,
		deadline: time.Now().Add(time.Second),
	}
}

func (r *Resp) DecRef() {
	msg := r.msg
	msg.Header = dnsmessage.Header{
		ID:            msg.Header.ID,
		Response:      true,
		Authoritative: true,
		RCode:         dnsmessage.RCodeSuccess,
	}
	msg.Answers = []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  msg.Questions[0].Name,
				Type:  msg.Questions[0].Type,
				Class: msg.Questions[0].Class,
				TTL:   60,
			},
		},
	}
	switch msg.Questions[0].Type {
	case dnsmessage.TypeA:
		msg.Answers[0].Body = &dnsmessage.AResource{}
	case dnsmessage.TypeCNAME:
		msg.Answers[0].Body = &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(".")}
	case dnsmessage.TypeTXT:
		msg.Answers[0].Body = &dnsmessage.TXTResource{}
	case dnsmessage.TypeAAAA:
		msg.Answers[0].Body = &dnsmessage.AAAAResource{}
	}
	r.SendMsg(msg, r.addr)
}

func (r *Resp) Encode(encoded []byte, data []byte) []byte {
	msg := r.msg
	msg.Header = dnsmessage.Header{
		ID:            msg.Header.ID,
		Response:      true,
		Authoritative: true,
		RCode:         dnsmessage.RCodeSuccess,
	}
	msg.Answers = nil
	msg.Authorities = nil
	msg.Additionals = nil
	switch msg.Questions[0].Type {
	case dnsmessage.TypeA:
		fragN := 1
		if (len(data) - (4 - 4)) > 0 {
			fragN += (len(data) - (4 - 4)) / (4 - 1)
			if (len(data)-(4-4))%(4-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			A := [4]byte{byte(i)}
			if i == 0 {
				A[1] = byte(fragN)
				A[2] = byte(len(data) >> 8)
				A[3] = byte(len(data))
				n := copy(A[4:], data)
				data = data[n:]
			} else {
				n := copy(A[1:], data)
				data = data[n:]
			}
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  msg.Questions[0].Type,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: A},
			})
		}
	case dnsmessage.TypeCNAME:
		fragN := 1
		if (len(data) - (r.domain.cap - 4)) > 0 {
			fragN += (len(data) - (r.domain.cap - 4)) / (r.domain.cap - 1)
			if (len(data)-(r.domain.cap-4))%(r.domain.cap-1) > 0 {
				fragN++
			}
		}

		DATA := make([]byte, r.domain.cap)
		for i := range fragN {
			DATA[0] = byte(i)
			if i == 0 {
				DATA[1] = byte(fragN)
				DATA[2] = byte(len(data) >> 8)
				DATA[3] = byte(len(data))
				n := copy(DATA[4:], data)
				data = data[n:]
				msg.Answers = append(msg.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  msg.Questions[0].Name,
						Type:  msg.Questions[0].Type,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.CNAMEResource{CNAME: r.domain.Encode(DATA[:n+2])},
				})
			} else {
				n := copy(DATA[1:], data)
				data = data[n:]
				msg.Answers = append(msg.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  msg.Questions[0].Name,
						Type:  msg.Questions[0].Type,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.CNAMEResource{CNAME: r.domain.Encode(DATA[:n+1])},
				})
			}
		}
	case dnsmessage.TypeTXT:
		var txt []string
		for len(data) > 0 {
			size := min(len(data), 255)
			txt = append(txt, string(data[:size]))
			data = data[size:]
		}
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  msg.Questions[0].Name,
				Type:  msg.Questions[0].Type,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			Body: &dnsmessage.TXTResource{TXT: txt},
		})
	case dnsmessage.TypeAAAA:
		fragN := 1
		if (len(data) - (16 - 4)) > 0 {
			fragN += (len(data) - (16 - 4)) / (16 - 1)
			if (len(data)-(16-4))%(16-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			AAAA := [16]byte{byte(i)}
			if i == 0 {
				AAAA[1] = byte(fragN)
				AAAA[2] = byte(len(data) >> 8)
				AAAA[3] = byte(len(data))
				n := copy(AAAA[4:], data)
				data = data[n:]
			} else {
				n := copy(AAAA[1:], data)
				data = data[n:]
			}
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  msg.Questions[0].Type,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: AAAA},
			})
		}
	}
	if r.edns0 > 0 {
		msg.Additionals = append(msg.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(r.edns0),
				TTL:   0,
			},
			Body: &dnsmessage.OPTResource{},
		})
	}
	return common.Must2(msg.AppendPack(encoded[:0]))
}

func (r *Resp) Decode(decoded []byte) int {
	decoded = decoded[:0]
	msg := r.msg
	if msg.Questions[0].Type == dnsmessage.TypeTXT {
		if len(msg.Answers) == 1 && r.domain.IsDomain(msg.Answers[0].Header.Name) && msg.Answers[0].Header.Type == dnsmessage.TypeTXT {
			for i := range msg.Answers[0].Body.(*dnsmessage.TXTResource).TXT {
				decoded = append(decoded, msg.Answers[0].Body.(*dnsmessage.TXTResource).TXT[i]...)
			}
		}
		return len(decoded)
	} else {
		var frags [][]byte
		for i := range msg.Answers {
			if !r.domain.IsDomain(msg.Answers[i].Header.Name) || msg.Answers[i].Header.Type != msg.Questions[0].Type {
				continue
			}
			switch msg.Questions[0].Type {
			case dnsmessage.TypeA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AResource).A[:])
			case dnsmessage.TypeCNAME:
				var decoded [255]byte
				n := r.domain.Decode(&decoded, msg.Answers[i].Body.(*dnsmessage.CNAMEResource).CNAME)
				if n == 0 {
					continue
				}
				frags = append(frags, decoded[:n])
			case dnsmessage.TypeAAAA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AAAAResource).AAAA[:])
			}
		}
		if len(frags) == 0 || len(frags) > 255 {
			return 0
		}
		sort.Slice(frags, func(i, j int) bool {
			return frags[i][0] < frags[j][0]
		})
		if len(frags[0]) < 2 || frags[0][1] != byte(len(frags)) {
			return 0
		}
		decoded = append(decoded, frags[0][2:]...)
		for i := range frags {
			if i > 0 {
				if frags[i][0] == frags[i-1][0] {
					return 0
				}
				decoded = append(decoded, frags[i][1:]...)
			}
		}
		if len(decoded) < 2 {
			return 0
		}
		l := int(decoded[0])<<8 | int(decoded[1])
		copy(decoded, decoded[2:])
		decoded = decoded[:len(decoded)-2]
		if l > len(decoded) {
			return 0
		}
		return l
	}
}

type RespInfo struct {
	rs       chan *Resp
	fragID   byte
	capFrags int
	closed   bool
	mu       sync.Mutex
}

func (info *RespInfo) close() bool {
	info.mu.Lock()
	defer info.mu.Unlock()
	if info.closed {
		return true
	}
	if len(info.rs) == 0 {
		info.closed = true
		close(info.rs)
	}
	return info.closed
}

func (info *RespInfo) push(r *Resp) {
	info.mu.Lock()
	defer info.mu.Unlock()
	if info.closed {
		return
	}
	select {
	case info.rs <- r:
		info.capFrags += r.cap - 11
	default:
		resp := <-info.rs
		resp.DecRef()
		info.capFrags -= resp.cap - 11
		info.rs <- r
		info.capFrags += r.cap - 11
	}
	errors.LogDebug(context.Background(), len(info.rs), " ", info.capFrags, " +", r.cap)
}

func (info *RespInfo) pop(minAvailable int, lenp int) ([]*Resp, byte) {
	info.mu.Lock()
	defer info.mu.Unlock()
	if info.closed || len(info.rs) < minAvailable || info.capFrags < lenp {
		return nil, 0
	}
	var rs []*Resp
	size := 0
	for {
		r := <-info.rs
		rs = append(rs, r)
		size += r.cap - 11

		if len(rs) == 1 && lenp <= r.cap-8 {
			break
		}
		if lenp <= size {
			break
		}
	}
	fragID := byte(0)
	if len(rs) > 1 {
		fragID = info.fragID
		info.fragID++
	}
	return rs, fragID
}

func (info *RespInfo) flush(now time.Time) {
	info.mu.Lock()
	defer info.mu.Unlock()
	if info.closed {
		return
	}
	for {
		select {
		case r := <-info.rs:
			r.DecRef()
			info.capFrags -= r.cap - 11
			if now.Before(r.deadline) {
				return
			}
		default:
			return
		}
	}
}

type RespManager struct {
	m  map[ClientID]*RespInfo
	ch chan struct{}
	mu sync.RWMutex
}

func NewRespManager() *RespManager {
	m := &RespManager{
		m:  make(map[ClientID]*RespInfo),
		ch: make(chan struct{}),
	}
	go m.gc()
	return m
}

func (m *RespManager) closed() bool {
	select {
	case <-m.ch:
		return true
	default:
		return false
	}
}

func (m *RespManager) gc() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ch:
			return
		case now := <-ticker.C:
			m.mu.RLock()
			for _, info := range m.m {
				info.flush(now)
			}
			m.mu.RUnlock()

			m.mu.Lock()
			for key, info := range m.m {
				if info.close() {
					delete(m.m, key)
				}
			}
			m.mu.Unlock()

			ticker.Reset(time.Second)
		}
	}
}

func (m *RespManager) Push(clientID ClientID, r *Resp) {
	m.mu.RLock()
	info := m.m[clientID]
	if info != nil {
		info.push(r)
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return
	}
	if info != nil {
		info.push(r)
		return
	}
	info = &RespInfo{
		rs: make(chan *Resp, 255),
	}
	info.push(r)
	m.m[clientID] = info
}

func (m *RespManager) Pop(clientID ClientID, minAvailable int, lenp int) ([]*Resp, byte) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info := m.m[clientID]
	if info == nil {
		return nil, 0
	}
	return info.pop(minAvailable, lenp)
}

func (m *RespManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return
	}
	close(m.ch)
	for k := range m.m {
		delete(m.m, k)
	}
}

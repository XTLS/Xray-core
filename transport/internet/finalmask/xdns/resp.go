package xdns

import (
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	respTTL = 8 * time.Second
)

type Resp struct {
	msg      dnsmessage.Message
	addr     net.Addr
	clientID ClientID
	domain   *Domain

	edns0 uint16
	cap   int
}

func NewResp(msg dnsmessage.Message, addr net.Addr, clientID ClientID, domain *Domain) *Resp {
	if len(msg.Questions) != 1 {
		return nil
	}

	opt := false
	var edns0 uint16
	for i := range msg.Additionals {
		if msg.Additionals[i].Header.Type == dnsmessage.TypeOPT {
			if (msg.Additionals[i].Header.TTL>>16)&0xFF != 0 {
				return nil
			}
			if opt {
				return nil
			}
			opt = true
			edns0 = uint16(msg.Additionals[i].Header.Class)
		}
	}
	if edns0 > 4096 {
		return nil
	}
	if edns0 > 0 && edns0 < 512 {
		edns0 = 512
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
		cap = 4*n - n - 1
	case dnsmessage.TypeCNAME:
		single := 2 + 2 + 2 + 4 + 2 + domain.lenMax
		n := left / single
		if n > 255 {
			n = 255
		}
		cap = domain.cap*n - n - 1
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
		cap = 16*n - n - 1
	}
	if cap < 11+1 {
		return nil
	}

	msg.Header = dnsmessage.Header{
		ID:            msg.Header.ID,
		Response:      true,
		Authoritative: true,
		RCode:         dnsmessage.RCodeSuccess,
	}
	msg.Answers = nil
	msg.Authorities = nil
	msg.Additionals = nil
	return &Resp{
		msg:      msg,
		addr:     addr,
		clientID: clientID,
		domain:   domain,

		edns0: edns0,
		cap:   cap,
	}
}

// TODO: use dnsmessage.Builder
func (r *Resp) Append(out []byte, data []byte) []byte {
	if len(data) == 0 || len(data) > r.cap {
		panic(len(data))
	}
	msg := r.msg
	switch r.msg.Questions[0].Type {
	case dnsmessage.TypeA:
		fragN := 1
		if (len(data) - (4 - 2)) > 0 {
			fragN += (len(data) - (4 - 2)) / (4 - 1)
			if (len(data)-(4-2))%(4-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			A := [4]byte{byte(i)}
			if i == 0 {
				A[1] = byte(fragN)
				n := copy(A[2:], data)
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
		if (len(data) - (r.domain.cap - 2)) > 0 {
			fragN += (len(data) - (r.domain.cap - 2)) / (r.domain.cap - 1)
			if (len(data)-(r.domain.cap-2))%(r.domain.cap-1) > 0 {
				fragN++
			}
		}

		DATA := make([]byte, r.domain.cap)
		for i := range fragN {
			DATA[0] = byte(i)
			if i == 0 {
				DATA[1] = byte(fragN)
				n := copy(DATA[2:], data)
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
		if (len(data) - (16 - 2)) > 0 {
			fragN += (len(data) - (16 - 2)) / (16 - 1)
			if (len(data)-(16-2))%(16-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			AAAA := [16]byte{byte(i)}
			if i == 0 {
				AAAA[1] = byte(fragN)
				n := copy(AAAA[2:], data)
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
	return common.Must2(msg.AppendPack(out))
}

type RespInfo struct {
	resp     chan *Resp
	fragID   byte
	capFrags int
	deadline time.Time
}

type RespManager struct {
	m       map[ClientID]RespInfo
	closeCh chan struct{}
	mu      sync.Mutex
}

func NewRespManager() *RespManager {
	m := &RespManager{
		m:       make(map[ClientID]RespInfo),
		closeCh: make(chan struct{}),
	}
	go m.gc()
	return m
}

func (m *RespManager) closed() bool {
	select {
	case <-m.closeCh:
		return true
	default:
		return false
	}
}

func (m *RespManager) gc() {
	ticker := time.NewTicker(respTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-m.closeCh:
			return
		case now := <-ticker.C:
			m.mu.Lock()
			for key, info := range m.m {
				if now.After(info.deadline) {
					delete(m.m, key)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *RespManager) Push(clientID ClientID, resp *Resp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return
	}
	now := time.Now()
	info, ok := m.m[clientID]
	if !ok || now.After(info.deadline) {
		info = RespInfo{
			resp:     make(chan *Resp, 255),
			deadline: now.Add(respTTL),
		}
	}
	select {
	case info.resp <- resp:
		info.capFrags += resp.cap - 11
	default:
		r := <-info.resp
		info.capFrags -= r.cap - 11
		info.resp <- resp
		info.capFrags += resp.cap - 11
	}
	m.m[clientID] = info
}

func (m *RespManager) Pop(clientID ClientID, lenp int, minAvailable int) ([]*Resp, byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return nil, 0
	}
	now := time.Now()
	info, ok := m.m[clientID]
	if !ok || now.After(info.deadline) {
		if ok {
			delete(m.m, clientID)
		}
		return nil, 0
	}
	if len(info.resp) < minAvailable || info.capFrags < lenp {
		return nil, 0
	}
	var resps []*Resp
	size := 0
	for {
		r := <-info.resp
		info.capFrags -= r.cap - 11
		resps = append(resps, r)
		size += r.cap - 11
		if len(resps) == 0 && lenp <= r.cap-8 {
			break
		}
		if lenp <= size {
			break
		}
	}
	fragID := byte(0)
	if len(resps) > 1 {
		fragID = info.fragID
		info.fragID++
	}
	info.deadline = now.Add(respTTL)
	m.m[clientID] = info
	return resps, fragID
}

func (m *RespManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return
	}
	close(m.closeCh)
	for k := range m.m {
		delete(m.m, k)
	}
}

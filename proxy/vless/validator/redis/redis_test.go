package redis

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

func TestReadReply(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    interface{}
		wantErr bool
	}{
		{"simple string", "+OK\r\n", "OK", false},
		{"error", "-ERR boom\r\n", nil, true},
		{"integer", ":42\r\n", int64(42), false},
		{"bulk string", "$5\r\nhello\r\n", []byte("hello"), false},
		{"empty bulk string", "$0\r\n\r\n", []byte{}, false},
		{"null bulk", "$-1\r\n", nil, false},
		{"array", "*2\r\n$1\r\na\r\n$1\r\nb\r\n", []interface{}{[]byte("a"), []byte("b")}, false},
		{"null array", "*-1\r\n", nil, false},
		{"nested array", "*1\r\n*1\r\n+ok\r\n", []interface{}{[]interface{}{"ok"}}, false},
		{"unknown prefix", "!nope\r\n", nil, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readReply(bufio.NewReader(strings.NewReader(c.input)))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (value=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalReply(got, c.want) {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

func equalReply(a, b interface{}) bool {
	switch av := a.(type) {
	case []byte:
		bv, ok := b.([]byte)
		return ok && bytes.Equal(av, bv)
	case []interface{}:
		bv, ok := b.([]interface{})
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !equalReply(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func TestReadReplyTruncated(t *testing.T) {
	_, err := readReply(bufio.NewReader(strings.NewReader("$5\r\nhel")))
	if err == nil {
		t.Fatal("expected error on truncated bulk reply")
	}
}

func TestWriteCommand(t *testing.T) {
	var buf bytes.Buffer
	if _, err := writeCommand(&buf, "SET", "k", "v"); err != nil {
		t.Fatal(err)
	}
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

func TestParseAddress(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
		check   func(t *testing.T, v *Validator)
	}{
		{
			name: "bare host port",
			addr: "10.0.0.1:6380",
			check: func(t *testing.T, v *Validator) {
				if v.address != "10.0.0.1:6380" || v.tls {
					t.Fatalf("unexpected state: %+v", v)
				}
			},
		},
		{
			name: "redis scheme",
			addr: "redis://user:pass@10.0.0.1:6379/3",
			check: func(t *testing.T, v *Validator) {
				if v.address != "10.0.0.1:6379" || v.tls || v.username != "user" || v.password != "pass" || v.db != 3 {
					t.Fatalf("unexpected state: %+v", v)
				}
			},
		},
		{
			name: "rediss scheme enables tls",
			addr: "rediss://10.0.0.1:6379",
			check: func(t *testing.T, v *Validator) {
				if !v.tls {
					t.Fatalf("expected tls enabled: %+v", v)
				}
			},
		},
		{
			name:    "unsupported scheme",
			addr:    "http://10.0.0.1:6379",
			wantErr: true,
		},
		{
			name:    "invalid db",
			addr:    "redis://10.0.0.1:6379/notanumber",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &Validator{address: defaultAddress, prefix: defaultPrefix}
			err := v.parseAddress(c.addr)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			c.check(t, v)
		})
	}
}

// fakeRedisServer is a minimal single-connection-handler-per-conn RESP2
// server good enough to exercise the Validator's command set, including the
// two Lua scripts used for atomic Add/Del. Each command (including EVAL) is
// executed under a single mutex, mirroring Redis's own single-threaded
// script execution, which is the actual mechanism that makes Add/Del race
// free against concurrent clients.
type fakeRedisServer struct {
	mu       sync.Mutex
	kv       map[string][]byte
	sets     map[string]map[string]struct{}
	listener net.Listener
	dials    int32
}

func newFakeRedisServer(t *testing.T) *fakeRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeRedisServer{
		kv:       map[string][]byte{},
		sets:     map[string]map[string]struct{}{},
		listener: ln,
	}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeRedisServer) addr() string { return s.listener.Addr().String() }

func (s *fakeRedisServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		atomic.AddInt32(&s.dials, 1)
		go s.handleConn(conn)
	}
}

func (s *fakeRedisServer) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		if _, err := conn.Write(s.exec(args)); err != nil {
			return
		}
	}
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("bad command line: %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, n)
	for i := 0; i < n; i++ {
		sizeLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		sizeLine = strings.TrimRight(sizeLine, "\r\n")
		size, err := strconv.Atoi(sizeLine[1:])
		if err != nil {
			return nil, err
		}
		data := make([]byte, size+2)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		args[i] = string(data[:size])
	}
	return args, nil
}

func bulkReply(v []byte) []byte {
	return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(v), v))
}

func nullBulkReply() []byte { return []byte("$-1\r\n") }

func integerReply(n int) []byte { return []byte(fmt.Sprintf(":%d\r\n", n)) }

func arrayReply(items [][]byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(items))
	for _, it := range items {
		b.Write(bulkReply(it))
	}
	return b.Bytes()
}

func (s *fakeRedisServer) exec(args []string) []byte {
	if len(args) == 0 {
		return []byte("-ERR empty command\r\n")
	}
	cmd := strings.ToUpper(args[0])

	s.mu.Lock()
	defer s.mu.Unlock()

	switch cmd {
	case "PING":
		return []byte("+PONG\r\n")
	case "AUTH", "SELECT":
		return []byte("+OK\r\n")
	case "SET":
		s.kv[args[1]] = []byte(args[2])
		return []byte("+OK\r\n")
	case "GET":
		v, ok := s.kv[args[1]]
		if !ok {
			return nullBulkReply()
		}
		return bulkReply(v)
	case "DEL":
		n := 0
		for _, k := range args[1:] {
			if _, ok := s.kv[k]; ok {
				delete(s.kv, k)
				n++
			}
		}
		return integerReply(n)
	case "SADD":
		set := s.sets[args[1]]
		if set == nil {
			set = map[string]struct{}{}
			s.sets[args[1]] = set
		}
		n := 0
		for _, m := range args[2:] {
			if _, ok := set[m]; !ok {
				set[m] = struct{}{}
				n++
			}
		}
		return integerReply(n)
	case "SREM":
		set := s.sets[args[1]]
		n := 0
		for _, m := range args[2:] {
			if _, ok := set[m]; ok {
				delete(set, m)
				n++
			}
		}
		return integerReply(n)
	case "SMEMBERS":
		set := s.sets[args[1]]
		items := make([][]byte, 0, len(set))
		for m := range set {
			items = append(items, []byte(m))
		}
		return arrayReply(items)
	case "SCARD":
		return integerReply(len(s.sets[args[1]]))
	case "EVAL":
		return s.evalLocked(args[1:])
	default:
		return []byte("-ERR unknown command\r\n")
	}
}

func (s *fakeRedisServer) evalLocked(args []string) []byte {
	script, numkeysStr := args[0], args[1]
	numkeys, err := strconv.Atoi(numkeysStr)
	if err != nil {
		return []byte("-ERR bad numkeys\r\n")
	}
	keys := args[2 : 2+numkeys]
	argv := args[2+numkeys:]

	switch script {
	case addUserScript:
		emailKey, emailsKey, userKey := keys[0], keys[1], keys[2]
		id, email, value := argv[0], argv[1], argv[2]
		if existing, ok := s.kv[emailKey]; ok && string(existing) != id {
			return []byte("-EXISTS\r\n")
		}
		s.kv[emailKey] = []byte(id)
		set := s.sets[emailsKey]
		if set == nil {
			set = map[string]struct{}{}
			s.sets[emailsKey] = set
		}
		set[email] = struct{}{}
		s.kv[userKey] = []byte(value)
		return []byte("+OK\r\n")
	case delUserScript:
		emailKey, userKeyBase, emailsKey := keys[0], keys[1], keys[2]
		email := argv[0]
		idBytes, ok := s.kv[emailKey]
		if !ok {
			return nullBulkReply()
		}
		id := string(idBytes)
		delete(s.kv, emailKey)
		delete(s.kv, userKeyBase+":"+id)
		if set := s.sets[emailsKey]; set != nil {
			delete(set, email)
		}
		return bulkReply(idBytes)
	default:
		return []byte("-ERR unknown script\r\n")
	}
}

func newTestValidator(t *testing.T, addr string) *Validator {
	t.Helper()
	v, err := NewValidator(&Config{Address: addr})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func newMemoryUser(t *testing.T, email string) *protocol.MemoryUser {
	t.Helper()
	id := uuid.New()
	return &protocol.MemoryUser{
		Email: email,
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(id),
		},
	}
}

func TestValidatorAddGetDelRoundTrip(t *testing.T) {
	s := newFakeRedisServer(t)
	v := newTestValidator(t, s.addr())

	user := newMemoryUser(t, "user@example.com")
	if err := v.Add(user); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got := v.GetByEmail("USER@example.com")
	if got == nil || got.Email != "user@example.com" {
		t.Fatalf("GetByEmail returned %+v", got)
	}

	id := user.Account.(*vless.MemoryAccount).ID.UUID()
	byID := v.Get(id)
	if byID == nil || byID.Email != "user@example.com" {
		t.Fatalf("Get returned %+v", byID)
	}

	if n := v.GetCount(); n != 1 {
		t.Fatalf("GetCount = %d, want 1", n)
	}
	if all := v.GetAll(); len(all) != 1 {
		t.Fatalf("GetAll = %v, want 1 entry", all)
	}

	if err := v.Del(user.Email); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if u := v.GetByEmail(user.Email); u != nil {
		t.Fatalf("expected nil after Del, got %+v", u)
	}
	if err := v.Del(user.Email); err == nil {
		t.Fatal("expected error deleting already-deleted user")
	}
}

func TestValidatorAddDuplicateEmailRejected(t *testing.T) {
	s := newFakeRedisServer(t)
	v := newTestValidator(t, s.addr())

	u1 := newMemoryUser(t, "dup@example.com")
	u2 := newMemoryUser(t, "dup@example.com")

	if err := v.Add(u1); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := v.Add(u2); err == nil {
		t.Fatal("expected error on duplicate email")
	}
	if n := v.GetCount(); n != 1 {
		t.Fatalf("GetCount = %d, want 1", n)
	}
}

// TestValidatorAddConcurrentSameEmail exercises the fix for the Add/Del
// TOCTOU race: many goroutines race to register the same email with
// different UUIDs. Exactly one must win. Run with -race.
func TestValidatorAddConcurrentSameEmail(t *testing.T) {
	s := newFakeRedisServer(t)
	v := newTestValidator(t, s.addr())

	const n = 50
	users := make([]*protocol.MemoryUser, n)
	for i := range users {
		users[i] = newMemoryUser(t, "race@example.com")
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = v.Add(users[i])
		}(i)
	}
	wg.Wait()

	success := 0
	for _, err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly 1 successful Add, got %d", success)
	}
	if n := v.GetCount(); n != 1 {
		t.Fatalf("GetCount = %d, want 1", n)
	}
}

func TestValidatorConnectionReuse(t *testing.T) {
	s := newFakeRedisServer(t)
	v := newTestValidator(t, s.addr())

	for i := 0; i < 20; i++ {
		if _, err := v.command("PING"); err != nil {
			t.Fatalf("command: %v", err)
		}
	}

	if got := atomic.LoadInt32(&s.dials); got != 1 {
		t.Fatalf("expected exactly 1 dial (pooled connection reused), got %d", got)
	}
}

func TestValidatorCommandTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept but never respond, to force a client-side timeout.
			_ = conn
		}
	}()

	old := commandTimeout
	commandTimeout = 100 * time.Millisecond
	defer func() { commandTimeout = old }()

	v := &Validator{address: ln.Addr().String(), prefix: defaultPrefix, pool: make(chan *redisConn, defaultPoolSize)}

	start := time.Now()
	_, err = v.command("PING")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("command took too long to time out: %v", elapsed)
	}
}

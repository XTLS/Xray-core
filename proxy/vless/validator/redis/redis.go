// Package redis implements a vless.Validator backed by Redis, so a node can
// look up VLESS users from a central store instead of holding them in memory.
//
// The address accepted by Config.Address is either a bare "host:port" (no
// auth, db 0, no TLS) or a URL of the form:
//
//	redis://[user:password@]host:port[/db]
//	rediss://[user:password@]host:port[/db]  (TLS)
//
// GetAll/GetCount are backed by the "emails" index (see MemoryValidator),
// so a user added without an Email is invisible to those two calls.
package redis

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/protobuf/proto"
)

const (
	defaultAddress  = "127.0.0.1:6379"
	defaultPrefix   = "vless"
	defaultPoolSize = 8
)

// commandTimeout bounds each Redis round trip (dial, auth, select, and the
// command itself). It is a var, not a const, so tests can shrink it.
var commandTimeout = 5 * time.Second

// addUserScript atomically checks the email index and writes the user,
// closing the GET-then-SET race a plain command sequence would have.
const addUserScript = `
local existing = redis.call('GET', KEYS[1])
if existing and existing ~= ARGV[1] then
	return redis.error_reply('EXISTS')
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('SADD', KEYS[2], ARGV[2])
redis.call('SET', KEYS[3], ARGV[3])
return 'OK'
`

// delUserScript atomically resolves the email to a user id and removes both
// index and user entries.
const delUserScript = `
local id = redis.call('GET', KEYS[1])
if not id then
	return false
end
redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2] .. ':' .. id)
redis.call('SREM', KEYS[3], ARGV[1])
return id
`

// redisError represents an application-level "-ERR ..." reply. Unlike other
// errors returned by command(), receiving one does not mean the underlying
// connection is broken and it is safe to return the connection to the pool.
type redisError struct {
	msg string
}

func (e *redisError) Error() string { return e.msg }

// Validator stores VLESS users in Redis.
type Validator struct {
	address  string
	username string
	password string
	db       int
	tls      bool
	prefix   string
	pool     chan *redisConn
}

type redisConn struct {
	net.Conn
	reader *bufio.Reader
}

func NewValidator(config *Config) (*Validator, error) {
	v := &Validator{
		address: defaultAddress,
		prefix:  defaultPrefix,
		pool:    make(chan *redisConn, defaultPoolSize),
	}
	if config != nil && strings.TrimSpace(config.Address) != "" {
		if err := v.parseAddress(strings.TrimSpace(config.Address)); err != nil {
			return nil, err
		}
	}
	if err := v.ping(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Validator) parseAddress(address string) error {
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil {
			return err
		}
		switch u.Scheme {
		case "redis":
			v.tls = false
		case "rediss":
			v.tls = true
		default:
			return errors.New("unsupported Redis scheme: ", u.Scheme)
		}
		if u.Host == "" {
			return errors.New("empty Redis host")
		}
		v.address = u.Host
		if u.User != nil {
			v.username = u.User.Username()
			v.password, _ = u.User.Password()
		}
		if db := strings.TrimPrefix(u.Path, "/"); db != "" {
			parsed, err := strconv.Atoi(db)
			if err != nil {
				return errors.New("invalid Redis database: ", db).Base(err)
			}
			v.db = parsed
		}
		return nil
	}

	v.address = address
	return nil
}

func (v *Validator) ping() error {
	_, err := v.command("PING")
	return err
}

func (v *Validator) key(parts ...string) string {
	items := append([]string{v.prefix}, parts...)
	return strings.Join(items, ":")
}

func idKey(id uuid.UUID) string {
	processed := uuid.UUID(vless.ProcessUUID(id))
	return processed.String()
}

func (v *Validator) getConn(ctx context.Context) (*redisConn, error) {
	select {
	case conn := <-v.pool:
		return conn, nil
	default:
	}
	return v.dial(ctx)
}

func (v *Validator) putConn(conn *redisConn, broken bool) {
	if conn == nil {
		return
	}
	if broken {
		conn.Close()
		return
	}
	select {
	case v.pool <- conn:
	default:
		conn.Close()
	}
}

func (v *Validator) dial(ctx context.Context) (*redisConn, error) {
	var conn net.Conn
	var err error
	dialer := &net.Dialer{}
	if v.tls {
		conn, err = tls.DialWithDialer(dialer, "tcp", v.address, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", v.address)
	}
	if err != nil {
		return nil, err
	}

	rc := &redisConn{Conn: conn, reader: bufio.NewReader(conn)}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if v.password != "" || v.username != "" {
		authArgs := []string{"AUTH"}
		if v.username != "" {
			authArgs = append(authArgs, v.username)
		}
		authArgs = append(authArgs, v.password)
		if _, err := writeCommand(conn, authArgs...); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := readReply(rc.reader); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if v.db != 0 {
		if _, err := writeCommand(conn, "SELECT", strconv.Itoa(v.db)); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := readReply(rc.reader); err != nil {
			conn.Close()
			return nil, err
		}
	}

	_ = conn.SetDeadline(time.Time{})
	return rc, nil
}

func (v *Validator) command(args ...string) (interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	conn, err := v.getConn(ctx)
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := writeCommand(conn, args...); err != nil {
		v.putConn(conn, true)
		return nil, err
	}
	reply, err := readReply(conn.reader)
	if err != nil {
		if _, ok := err.(*redisError); ok {
			_ = conn.SetDeadline(time.Time{})
			v.putConn(conn, false)
			return nil, err
		}
		v.putConn(conn, true)
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	v.putConn(conn, false)
	return reply, nil
}

func writeCommand(w io.Writer, args ...string) (int, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return w.Write(buf.Bytes())
}

func readReply(r *bufio.Reader) (interface{}, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")

	switch prefix {
	case '+':
		return line, nil
	case '-':
		return nil, &redisError{msg: "Redis error: " + line}
	case ':':
		return strconv.ParseInt(line, 10, 64)
	case '$':
		size, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if size == -1 {
			return nil, nil
		}
		data := make([]byte, size+2)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		return data[:size], nil
	case '*':
		size, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if size == -1 {
			return nil, nil
		}
		items := make([]interface{}, 0, size)
		for i := 0; i < size; i++ {
			item, err := readReply(r)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	default:
		return nil, errors.New("unknown Redis reply type: ", string(prefix))
	}
}

func encodeUser(u *protocol.MemoryUser) (string, error) {
	user := protocol.ToProtoUser(u)
	data, err := proto.Marshal(user)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func decodeUser(value interface{}) (*protocol.MemoryUser, error) {
	if value == nil {
		return nil, nil
	}
	raw, ok := value.([]byte)
	if !ok {
		return nil, errors.New("unexpected Redis value type")
	}
	data, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, err
	}
	user := new(protocol.User)
	if err := proto.Unmarshal(data, user); err != nil {
		return nil, err
	}
	return user.ToMemoryUser()
}

func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("VLESS user is nil")
	}
	id := idKey(u.Account.(*vless.MemoryAccount).ID.UUID())
	value, err := encodeUser(u)
	if err != nil {
		return err
	}

	if u.Email == "" {
		_, err = v.command("SET", v.key("user", id), value)
		return err
	}

	email := strings.ToLower(u.Email)
	_, err = v.command(
		"EVAL", addUserScript, "3",
		v.key("email", email), v.key("emails"), v.key("user", id),
		id, email, value,
	)
	if err != nil {
		if _, ok := err.(*redisError); ok {
			return errors.New("User ", u.Email, " already exists.")
		}
		return err
	}
	return nil
}

func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}
	email = strings.ToLower(email)
	reply, err := v.command(
		"EVAL", delUserScript, "3",
		v.key("email", email), v.key("user"), v.key("emails"),
		email,
	)
	if err != nil {
		return err
	}
	if reply == nil {
		return errors.New("User ", email, " not found.")
	}
	return nil
}

func (v *Validator) Get(id uuid.UUID) *protocol.MemoryUser {
	value, err := v.command("GET", v.key("user", idKey(id)))
	if err != nil {
		return nil
	}
	user, err := decodeUser(value)
	if err != nil {
		return nil
	}
	return user
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	id, err := v.command("GET", v.key("email", email))
	if err != nil || id == nil {
		return nil
	}
	value, err := v.command("GET", v.key("user", string(id.([]byte))))
	if err != nil {
		return nil
	}
	user, err := decodeUser(value)
	if err != nil {
		return nil
	}
	return user
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	emails, err := v.command("SMEMBERS", v.key("emails"))
	if err != nil {
		return nil
	}
	items, ok := emails.([]interface{})
	if !ok {
		return nil
	}
	users := make([]*protocol.MemoryUser, 0, len(items))
	for _, item := range items {
		email, ok := item.([]byte)
		if !ok {
			continue
		}
		if user := v.GetByEmail(string(email)); user != nil {
			users = append(users, user)
		}
	}
	return users
}

func (v *Validator) GetCount() int64 {
	count, err := v.command("SCARD", v.key("emails"))
	if err != nil {
		return 0
	}
	if n, ok := count.(int64); ok {
		return n
	}
	return 0
}

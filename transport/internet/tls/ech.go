package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func ApplyECH(c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	if len(c.EchConfig) > 0 {
		ECHConfig = c.EchConfig
	} else { // ECH config > DOH lookup
		if config.ServerName == "" {
			return errors.New("Using DOH for ECH needs serverName")
		}
		ECHConfig, err = QueryRecord(c.ServerName, c.Ech_DOHserver)
		if err != nil {
			return err
		}
	}

	config.EncryptedClientHelloConfigList = ECHConfig
	return nil
}

type record struct {
	record []byte
	expire time.Time
}

var (
	dnsCache = make(map[string]record)
	mutex    sync.RWMutex
)

func QueryRecord(domain string, server string) ([]byte, error) {
    mutex.Lock()
    rec, found := dnsCache[domain]
    if found && rec.expire.After(time.Now()) {
        mutex.Unlock()
        return rec.record, nil
    }
    mutex.Unlock()

    errors.LogDebug(context.Background(), "Trying to query ECH config for domain: ", domain, " with ECH server: ", server)
    record, ttl, err := dohQuery(server, domain)
    if err != nil {
        return []byte{}, err
    }

    if ttl < 600 {
        ttl = 600
    }

    mutex.Lock()
    defer mutex.Unlock()
    rec.record = record
    rec.expire = time.Now().Add(time.Second * time.Duration(ttl))
    dnsCache[domain] = rec
    return record, nil
}

func dohQuery(server string, domain string) ([]byte, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.Id = 0
	msg, err := m.Pack()
	if err != nil {
		return []byte{}, 0, err
	}
	tr := &http.Transport{
		IdleConnTimeout:   90 * time.Second,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			conn, err := internet.DialSystem(ctx, dest, nil)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
	if err != nil {
		return []byte{}, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return []byte{}, 0, errors.New("query failed with response code:", resp.StatusCode)
	}
	respMsg := new(dns.Msg)
	err = respMsg.Unpack(respBody)
	if err != nil {
		return []byte{}, 0, err
	}
	if len(respMsg.Answer) > 0 {
		for _, answer := range respMsg.Answer {
			if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
				for _, v := range https.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
						errors.LogDebug(context.Background(), "Get ECH config:", echConfig.String(), " TTL:", respMsg.Answer[0].Header().Ttl)
						return echConfig.ECH, answer.Header().Ttl, nil
					}
				}
			}
		}
	}
	return []byte{}, 0, errors.New("no ech record found")
}

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/OmarTariq612/goech"
	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func ApplyECH(c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	nameToQuery := c.ServerName
	var DNSServer string

	// for client
	if len(c.EchConfigList) != 0 {
		// direct base64 config
		if strings.HasPrefix(c.EchConfigList, "base64") {
			Base64ECHConfigList := c.EchConfigList[len("base64://"):]
			ECHConfigList, err := goech.ECHConfigListFromBase64(Base64ECHConfigList)
			if err != nil {
				return errors.New("Failed to unmarshal ECHConfigList: ", err)
			}
			ECHConfig, _ = ECHConfigList.MarshalBinary()
		} else { // query config from dns
			parts := strings.Split(c.EchConfigList, "+")
			if len(parts) == 2 {
				// parse ECH DNS server in format of "example.com+https://1.1.1.1/dns-query"
				nameToQuery = parts[0]
				DNSServer = parts[1]
			} else if len(parts) == 1 {
				// normal format
				DNSServer = parts[0]
			} else {
				return errors.New("Invalid ECH DNS server format: ", c.EchConfigList)
			}
			if nameToQuery == "" {
				return errors.New("Using DNS for ECH Config needs serverName or use Server format example.com+https://1.1.1.1/dns-query")
			}
			ECHConfig, err = QueryRecord(nameToQuery, DNSServer)
			if err != nil {
				return err
			}
		}

		config.EncryptedClientHelloConfigList = ECHConfig
	}

	// for server
	if len(c.EchKeySets) != 0 {
		var keys []tls.EncryptedClientHelloKey
		KeySets, err := goech.UnmarshalECHKeySetList(c.EchKeySets)
		if err != nil {
			return errors.New("Failed to unmarshal ECHKeySetList: ", err)
		}
		for idx, keySet := range KeySets {
			ECHConfig, err := keySet.ECHConfig.MarshalBinary()
			ECHPrivateKey, err := keySet.PrivateKey.MarshalBinary()
			if err != nil {
				return errors.New("Failed to marshal ECHKey in index: ", idx, "with err: ", err)
			}
			keys = append(keys, tls.EncryptedClientHelloKey{
				Config:     ECHConfig,
				PrivateKey: ECHPrivateKey})
		}
		config.EncryptedClientHelloKeys = keys
	}
	
	return nil
}

type record struct {
	echConfig []byte
	expire    time.Time
}

var (
	dnsCache sync.Map
	// global Lock? I'm not sure if this needs finer grained locks.
	// If we do this, we will need to nest another layer of struct
	updating sync.Mutex
)

// QueryRecord returns the ECH config for given domain.
// If the record is not in cache or expired, it will query the DNS server and update the cache.
func QueryRecord(domain string, server string) ([]byte, error) {
	val, found := dnsCache.Load(domain)
	rec, _ := val.(record)
	if found && rec.expire.After(time.Now()) {
		errors.LogDebug(context.Background(), "Cache hit for domain: ", domain)
		return rec.echConfig, nil
	}

	updating.Lock()
	defer updating.Unlock()
	// Try to get cache again after lock, in case another goroutine has updated it
	// This might happen when the core tring is just stared and multiple goroutines are trying to query the same domain
	val, found = dnsCache.Load(domain)
	rec, _ = val.(record)
	if found && rec.expire.After(time.Now()) {
		errors.LogDebug(context.Background(), "ECH Config cache hit for domain: ", domain, " after trying to get update lock")
		return rec.echConfig, nil
	}

	// Query ECH config from DNS server
	errors.LogDebug(context.Background(), "Trying to query ECH config for domain: ", domain, " with ECH server: ", server)
	echConfig, ttl, err := dnsQuery(server, domain)
	if err != nil {
		return []byte{}, err
	}

	// Set minimum TTL to 600 seconds
	if ttl < 600 {
		ttl = 600
	}

	// Update cache
	newRecored := record{
		echConfig: echConfig,
		expire:    time.Now().Add(time.Second * time.Duration(ttl)),
	}
	dnsCache.Store(domain, newRecored)
	return echConfig, nil
}

// dnsQuery is the real func for sending type65 query for given domain to given DNS server.
// return ECH config, TTL and error
func dnsQuery(server string, domain string) ([]byte, uint32, error) {
	m := new(dns.Msg)
	var dnsResolve []byte
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	// for DOH server
	if strings.HasPrefix(server, "https://") {
		// always 0 in DOH
		m.Id = 0
		msg, err := m.Pack()
		if err != nil {
			return []byte{}, 0, err
		}
		// All traffic sent by core should via xray's internet.DialSystem
		// This involves the behavior of some Android VPN GUI clients
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
		dnsResolve = respBody
	} else if strings.HasPrefix(server, "udp://") { // for classic udp dns server
		udpServerAddr := server[len("udp://"):]
		// default port 53 if not specified
		if !strings.Contains(udpServerAddr, ":") {
			udpServerAddr = udpServerAddr + ":53"
		}
		dest, err := net.ParseDestination("udp" + ":" + udpServerAddr)
		if err != nil {
			return nil, 0, errors.New("failed to parse udp dns server ", udpServerAddr, " for ECH: ", err)
		}
		dnsTimeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// use xray's internet.DialSystem as mentioned above
		conn, err := internet.DialSystem(dnsTimeoutCtx, dest, nil)
		defer conn.Close()
		if err != nil {
			return []byte{}, 0, err
		}
		msg, err := m.Pack()
		if err != nil {
			return []byte{}, 0, err
		}
		conn.Write(msg)
		udpResponse := make([]byte, 512)
		_, err = conn.Read(udpResponse)
		if err != nil {
			return []byte{}, 0, err
		}
		dnsResolve = udpResponse
	}
	respMsg := new(dns.Msg)
	err := respMsg.Unpack(dnsResolve)
	if err != nil {
		return []byte{}, 0, errors.New("failed to unpack dns response for ECH: ", err)
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

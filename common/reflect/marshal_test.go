package reflect_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/common/reflect"
	cserial "github.com/xtls/xray-core/common/serial"
	iserial "github.com/xtls/xray-core/infra/conf/serial"
)

func TestMashalStruct(t *testing.T) {
	type Foo = struct {
		N   int                             `json:"n"`
		Np  *int                            `json:"np"`
		S   string                          `json:"s"`
		Arr *[]map[string]map[string]string `json:"arr"`
	}

	n := 1
	np := &n
	arr := make([]map[string]map[string]string, 0)
	m1 := make(map[string]map[string]string, 0)
	m2 := make(map[string]string, 0)
	m2["hello"] = "world"
	m1["foo"] = m2

	arr = append(arr, m1)

	f1 := Foo{
		N:   n,
		Np:  np,
		S:   "hello",
		Arr: &arr,
	}

	s, ok1 := MarshalToJson(f1)
	sp, ok2 := MarshalToJson(&f1)

	if !ok1 || !ok2 || s != sp {
		t.Error("marshal failed")
	}

	f2 := Foo{}
	if json.Unmarshal([]byte(s), &f2) != nil {
		t.Error("json unmarshal failed")
	}

	v := (*f2.Arr)[0]["foo"]["hello"]

	if f1.N != f2.N || *(f1.Np) != *(f2.Np) || f1.S != f2.S || v != "world" {
		t.Error("f1 not equal to f2")
	}
}

func TestMarshalConfigJson(t *testing.T) {

	buf := bytes.NewBufferString(getConfig())
	config, err := iserial.DecodeJSONConfig(buf)
	if err != nil {
		t.Error("decode JSON config failed")
	}

	bc, err := config.Build()
	if err != nil {
		t.Error("build core config failed")
	}

	tmsg := cserial.ToTypedMessage(bc)
	tc, ok := MarshalToJson(tmsg)
	if !ok {
		t.Error("marshal config failed")
	}

	// t.Log(tc)

	keywords := []string{
		"4784f9b8-a879-4fec-9718-ebddefa47750",
		"bing.com",
		"DomainStrategy",
		"InboundTag",
		"Level",
		"Stats",
		"UserDownlink",
		"UserUplink",
		"System",
		"InboundDownlink",
		"OutboundUplink",
	}
	for _, kw := range keywords {
		if !strings.Contains(tc, kw) {
			t.Error("marshaled config error")
		}
	}
}

func getConfig() string {
	return `{
		"log": {
		  "loglevel": "debug"
		},
		"stats": {},
		"policy": {
		  "levels": {
			"0": {
			  "statsUserUplink": true,
			  "statsUserDownlink": true
			}
		  },
		  "system": {
			"statsInboundUplink": true,
			"statsInboundDownlink": true,
			"statsOutboundUplink": true,
			"statsOutboundDownlink": true
		  }
		},
		"inbounds": [
		  {
			"tag": "agentin",
			"protocol": "http",
			"port": 8080,
			"listen": "127.0.0.1",
			"settings": {}
		  },
		  {
			"listen": "127.0.0.1",
			"port": 10085,
			"protocol": "dokodemo-door",
			"settings": {
			  "address": "127.0.0.1"
			},
			"tag": "api-in"
		  }
		],
		"api": {
		  "tag": "api",
		  "services": [
			"HandlerService",
			"StatsService"
		  ]
		},
		"routing": {
		  "rules": [
			{
			  "inboundTag": [
				"api-in"
			  ],
			  "outboundTag": "api",
			  "type": "field"
			}
		  ],
		  "domainStrategy": "AsIs"
		},
		"outbounds": [
		  {
			"protocol": "vless",
			"settings": {
			  "vnext": [
				{
				  "address": "1.2.3.4",
				  "port": 1234,
				  "users": [
					{
					  "id": "4784f9b8-a879-4fec-9718-ebddefa47750",
					  "encryption": "none"
					}
				  ]
				}
			  ]
			},
			"tag": "agentout",
			"streamSettings": {
			  "network": "ws",
			  "security": "none",
			  "wsSettings": {
				"path": "/?ed=2048",
				"headers": {
				  "Host": "bing.com"
				}
			  }
			}
		  }
		]
	  }`
}

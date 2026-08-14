package splithttp_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

func TestApplyXPaddingToResponse(t *testing.T) {
	newConfig := func(placement, key, header string) *Config {
		c := &Config{
			XPaddingObfsMode: true,
			XPaddingMethod:   string(PaddingMethodRepeatX),
		}
		c.XPaddingKey = key
		c.XPaddingHeader = header
		c.XPaddingPlacement = placement
		return c
	}

	tests := []struct {
		name          string
		placement     string
		key           string
		header        string
		length        int
		wantHeaderKey string
		wantCookie    string
	}{
		{
			name:          "query placement falls back to padding header",
			placement:     PlacementQuery,
			key:           "x_padding",
			header:        "X-Padding",
			length:        100,
			wantHeaderKey: "X-Padding",
		},
		{
			name:          "query placement uses custom header",
			placement:     PlacementQuery,
			key:           "x_padding",
			header:        "X-Custom-Padding",
			length:        100,
			wantHeaderKey: "X-Custom-Padding",
		},
		{
			name:          "header placement sets configured header",
			placement:     PlacementHeader,
			key:           "x_padding",
			header:        "X-Padding",
			length:        100,
			wantHeaderKey: "X-Padding",
		},
		{
			name:       "cookie placement sets cookie",
			placement:  PlacementCookie,
			key:        "x_padding",
			header:     "X-Padding",
			length:     100,
			wantCookie: "x_padding",
		},
		{
			name:          "zero length produces no output",
			placement:     PlacementQuery,
			key:           "x_padding",
			header:        "X-Padding",
			length:        0,
			wantHeaderKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newConfig(tt.placement, tt.key, tt.header)
			rec := httptest.NewRecorder()
			config := XPaddingConfig{
				Length: tt.length,
				Placement: XPaddingPlacement{
					Placement: tt.placement,
					Key:       tt.key,
					Header:    tt.header,
				},
				Method: PaddingMethodRepeatX,
			}
			c.ApplyXPaddingToResponse(rec, config)

			if tt.wantHeaderKey != "" {
				v := rec.Header().Get(tt.wantHeaderKey)
				assert.NotEmpty(t, v, "padding header %q should be set", tt.wantHeaderKey)
				assert.Len(t, v, tt.length)
			} else {
				assert.Empty(t, rec.Header().Values("X-Padding"), "no padding header should be set")
			}

			if tt.wantCookie != "" {
				cookies := rec.Result().Cookies()
				var found bool
				for _, ck := range cookies {
					if ck.Name == tt.wantCookie {
						found = true
						assert.NotEmpty(t, ck.Value)
						assert.Len(t, ck.Value, tt.length)
					}
				}
				assert.True(t, found, "cookie %q should be set", tt.wantCookie)
			}
		})
	}
}

func TestApplyXPaddingToRequestQueryPlacement(t *testing.T) {
	c := &Config{
		XPaddingObfsMode:  true,
		XPaddingMethod:    string(PaddingMethodRepeatX),
		XPaddingKey:       "x_padding",
		XPaddingHeader:    "X-Padding",
		XPaddingPlacement: PlacementQuery,
	}
	config := XPaddingConfig{
		Length: 100,
		Placement: XPaddingPlacement{
			Placement: PlacementQuery,
			Key:       "x_padding",
			Header:    "X-Padding",
		},
		Method: PaddingMethodRepeatX,
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/sh/?world", nil)
	c.ApplyXPaddingToRequest(req, config)
	c.ApplyXPaddingToResponse(rec, config)

	// request side: padding lands in the query string
	assert.Equal(t, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", req.URL.Query().Get("x_padding"))
	// response side: query placement falls back to the padding header
	assert.Len(t, rec.Header().Get("X-Padding"), 100)
}

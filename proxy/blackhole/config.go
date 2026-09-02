package blackhole

import (
	"fmt"
	"net/http"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// ResponseConfig is the configuration for blackhole responses.
type ResponseConfig interface {
	// WriteTo writes a predefined response to the specified buffer.
	WriteTo(buf.Writer) int32
}

// WriteTo implements ResponseConfig.WriteTo().
func (*NoneResponse) WriteTo(buf.Writer) int32 { return 0 }

// WriteTo implements ResponseConfig.WriteTo().
// Returns an HTTP response with the configured status code.
// If status code is not set (0), defaults to 403 Forbidden for backward compatibility.
func (r *HTTPResponse) WriteTo(writer buf.Writer) int32 {
	statusCode := int(r.GetStatusCode())
	if statusCode == 0 {
		statusCode = http.StatusForbidden // Default to 403 for backward compatibility
	}

	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}

	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\n\r\n",
		statusCode, statusText)

	b := buf.New()
	common.Must2(b.WriteString(response))
	n := b.Len()
	writer.WriteMultiBuffer(buf.MultiBuffer{b})
	return n
}

// GetInternalResponse converts response settings from proto to internal data structure.
func (c *Config) GetInternalResponse() (ResponseConfig, error) {
	if c.GetResponse() == nil {
		return new(NoneResponse), nil
	}

	config, err := c.GetResponse().GetInstance()
	if err != nil {
		return nil, err
	}
	return config.(ResponseConfig), nil
}

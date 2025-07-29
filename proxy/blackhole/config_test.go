package blackhole_test

import (
	"bufio"
	"net/http"
	"testing"

	"github.com/NamiraNet/xray-core/common"
	"github.com/NamiraNet/xray-core/common/buf"
	. "github.com/NamiraNet/xray-core/proxy/blackhole"
)

func TestHTTPResponse(t *testing.T) {
	buffer := buf.New()

	httpResponse := new(HTTPResponse)
	httpResponse.WriteTo(buf.NewWriter(buffer))

	reader := bufio.NewReader(buffer)
	response, err := http.ReadResponse(reader, nil)
	common.Must(err)

	if response.StatusCode != 403 {
		t.Error("expected status code 403, but got ", response.StatusCode)
	}
}

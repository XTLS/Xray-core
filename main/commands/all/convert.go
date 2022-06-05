package all

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
	"google.golang.org/protobuf/proto"
)

var cmdConvert = &base.Command{
	UsageLine: "{{.Exec}} convert [json file] [json file] ...",
	Short:     "Convert multiple json config to protobuf",
	Long: `
Convert multiple json config to protobuf.

Examples:

    {{.Exec}} convert config.json c1.json c2.json <url>.json
	`,
}

func init() {
	cmdConvert.Run = executeConvert // break init loop
}

func executeConvert(cmd *base.Command, args []string) {
	unnamedArgs := cmdConvert.Flag.Args()
	if len(unnamedArgs) < 1 {
		base.Fatalf("empty config list")
	}

	conf := &conf.Config{}
	for _, arg := range unnamedArgs {
		fmt.Fprintf(os.Stderr, "Read config: %s", arg)
		r, err := loadArg(arg)
		common.Must(err)
		c, err := serial.DecodeJSONConfig(r)
		if err != nil {
			base.Fatalf(err.Error())
		}
		conf.Override(c, arg)
	}

	pbConfig, err := conf.Build()
	if err != nil {
		base.Fatalf(err.Error())
	}

	bytesConfig, err := proto.Marshal(pbConfig)
	if err != nil {
		base.Fatalf("failed to marshal proto config: %s", err)
	}

	if _, err := os.Stdout.Write(bytesConfig); err != nil {
		base.Fatalf("failed to write proto config: %s", err)
	}
}

// loadArg loads one arg, maybe an remote url, or local file path
func loadArg(arg string) (out io.Reader, err error) {
	var data []byte
	switch {
	case strings.HasPrefix(arg, "http://"), strings.HasPrefix(arg, "https://"):
		data, err = FetchHTTPContent(arg)

	case arg == "stdin:":
		data, err = io.ReadAll(os.Stdin)

	default:
		data, err = os.ReadFile(arg)
	}

	if err != nil {
		return
	}
	out = bytes.NewBuffer(data)
	return
}

// FetchHTTPContent dials https for remote content
func FetchHTTPContent(target string) ([]byte, error) {
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return nil, newError("invalid URL: ", target).Base(err)
	}

	if s := strings.ToLower(parsedTarget.Scheme); s != "http" && s != "https" {
		return nil, newError("invalid scheme: ", parsedTarget.Scheme)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(&http.Request{
		Method: "GET",
		URL:    parsedTarget,
		Close:  true,
	})
	if err != nil {
		return nil, newError("failed to dial to ", target).Base(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, newError("unexpected HTTP status code: ", resp.StatusCode)
	}

	content, err := buf.ReadAllToBytes(resp.Body)
	if err != nil {
		return nil, newError("failed to read HTTP response").Base(err)
	}

	return content, nil
}

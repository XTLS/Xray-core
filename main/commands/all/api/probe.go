package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	observatoryService "github.com/xtls/xray-core/app/observatory/command"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var cmdProbe = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api probe [--server=127.0.0.1:8080] [-json] [-url URL] [-method HEAD|GET] [-n samples] [-timeout-ms N] [-interval-ms N] (<tag> | -c <file.json>)",
	Short:       "Check that an outbound works",
	Long: `
Send test HTTP requests through one outbound and show every attempt: the
time of the whole request (with connection setup, TLS and so on) and the
HTTP status, or the error.

The outbound is either an existing one, given by its tag, or a new one
described in a file. A new outbound is added to the running Xray under a
temporary tag "xdprobe-..." for the time of the check and removed right
after it; it is not seen by observatories, balancers and "api lso", and
nothing is written to files. Observatory results are never changed. A check
of an existing outbound adds a little traffic to its counters.

Requests go straight to the outbound, bypassing routing. Only one check
runs at a time.

> Ensure that "ObservatoryService" is enabled under "config.api.services"
> in the server configuration. The running Xray must be built with
> ProbeOutbound support.

Arguments:

	<tag>
		Tag of an existing outbound, e.g. cf_22

	-c <file.json>
		A new outbound: {"outbounds":[{...}]} or a single outbound object,
		as for "api ado". Exactly one outbound. Its tag is not used.

	-url <URL>
		http:// or https:// URL to request. Default: pingConfig.destination
		of burstObservatory, or https://connectivitycheck.gstatic.com/generate_204

	-method <HEAD|GET>
		HTTP method. Default HEAD

	-n <samples>
		Number of attempts, 1 to 10. Default 3

	-timeout-ms <N>
		Timeout of one attempt in milliseconds, up to 30000.
		Default: pingConfig.timeout of burstObservatory, or 5000

	-interval-ms <N>
		Pause between attempts in milliseconds, up to 5000. Default 200

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default: enough for all attempts

	-json
		Use json output:
		{"tag":"cf_22","destination":"...","method":"HEAD",
		 "samples":[{"ok":true,"rttMs":640,"httpStatus":204},{"ok":false,"error":"..."}]}

The exit code is 0 when the check ran, even if every attempt failed.

Example:

    {{.Exec}} {{.LongName}} -s 127.0.0.1:10085 cf_22
    {{.Exec}} {{.LongName}} -s 127.0.0.1:10085 -json -n 5 cf_22
    {{.Exec}} {{.LongName}} -s 127.0.0.1:10085 -url https://www.google.com/generate_204 cf_22
    {{.Exec}} {{.LongName}} -s 127.0.0.1:10085 -c new-outbound.json
`,
	Run: executeProbe,
}

func executeProbe(cmd *base.Command, args []string) {
	var (
		file       string
		dest       string
		method     string
		samples    uint
		timeoutMs  uint
		intervalMs uint
	)
	setSharedFlags(cmd)
	cmd.Flag.StringVar(&file, "c", "", "")
	cmd.Flag.StringVar(&dest, "url", "", "")
	cmd.Flag.StringVar(&method, "method", "", "")
	cmd.Flag.UintVar(&samples, "n", 0, "")
	cmd.Flag.UintVar(&timeoutMs, "timeout-ms", 0, "")
	cmd.Flag.UintVar(&intervalMs, "interval-ms", 0, "")
	cmd.Flag.Parse(args)
	timeoutSet := false
	cmd.Flag.Visit(func(f *flag.Flag) {
		if f.Name == "t" || f.Name == "timeout" {
			timeoutSet = true
		}
	})

	req, err := buildProbeRequest(cmd.Flag.Args(), file, dest, method, samples, timeoutMs, intervalMs, os.ReadFile)
	if err != nil {
		base.Fatalf("%s", err)
	}

	callTimeout := probeCallTimeout(req)
	if timeoutSet {
		callTimeout = time.Duration(apiTimeout) * time.Second
	}
	dialTimeout := time.Duration(apiTimeout) * time.Second
	if !timeoutSet || dialTimeout > 10*time.Second {
		dialTimeout = 10 * time.Second
	}
	dctx, dcancel := context.WithTimeout(context.Background(), dialTimeout)
	conn, err := grpc.DialContext(dctx, apiServerAddrPtr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	dcancel()
	if err != nil {
		base.Fatalf("failed to dial %s", apiServerAddrPtr)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	client := observatoryService.NewObservatoryServiceClient(conn)
	resp, err := client.ProbeOutbound(ctx, req)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			base.Fatalf("the running Xray does not support ProbeOutbound: restart Xray after updating the binary (%s)", err)
		}
		base.Fatalf("failed to probe outbound: %s", err)
	}
	if apiJSON {
		b, err := probeJSON(resp)
		if err != nil {
			base.Fatalf("error encode json: %s", err)
		}
		fmt.Println(string(b))
		return
	}
	fmt.Print(probeText(resp))
}

// buildProbeRequest checks the arguments of "api probe" and builds the
// request. readFile reads the -c file.
func buildProbeRequest(tags []string, file, dest, method string, samples, timeoutMs, intervalMs uint, readFile func(string) ([]byte, error)) (*observatoryService.ProbeOutboundRequest, error) {
	req := &observatoryService.ProbeOutboundRequest{
		Destination: dest,
		Method:      strings.ToUpper(method),
		Samples:     uint32(samples),
		TimeoutMs:   uint32(timeoutMs),
		IntervalMs:  uint32(intervalMs),
	}
	switch {
	case file != "" && len(tags) > 0:
		return nil, errors.New("specify either an outbound tag or -c <file.json>, not both")
	case file == "" && len(tags) == 0:
		return nil, errors.New("specify an outbound tag or -c <file.json>")
	case len(tags) > 1:
		return nil, errors.New("specify exactly one outbound tag")
	}
	if dest != "" && !strings.HasPrefix(dest, "http://") && !strings.HasPrefix(dest, "https://") {
		return nil, errors.New("-url must start with http:// or https://")
	}
	if req.Method != "" && req.Method != "HEAD" && req.Method != "GET" {
		return nil, errors.New("-method must be HEAD or GET")
	}
	if samples > 10 {
		return nil, errors.New("-n must be from 1 to 10")
	}
	if timeoutMs > 30000 {
		return nil, errors.New("-timeout-ms must be up to 30000")
	}
	if intervalMs > 5000 {
		return nil, errors.New("-interval-ms must be up to 5000")
	}
	if len(tags) == 1 {
		req.Tag = tags[0]
		if req.Tag == "" {
			return nil, errors.New("empty outbound tag")
		}
		return req, nil
	}
	var data []byte
	var err error
	if file == "stdin:" || file == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = readFile(file)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %s", file, err)
	}
	out, err := loadProbeOutbound(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", file, err)
	}
	req.Outbound = out
	return req, nil
}

// loadProbeOutbound builds the one outbound of {"outbounds":[{...}]} or of
// a single outbound object.
func loadProbeOutbound(data []byte) (*core.OutboundHandlerConfig, error) {
	c, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %s", err)
	}
	outs := c.OutboundConfigs
	if len(outs) == 0 {
		// a single outbound object
		wrapped := append(append([]byte("{\"outbounds\":[\n"), data...), []byte("\n]}")...)
		c, err = serial.DecodeJSONConfig(bytes.NewReader(wrapped))
		if err != nil {
			return nil, fmt.Errorf("failed to decode: %s", err)
		}
		outs = c.OutboundConfigs
	}
	if len(outs) != 1 {
		return nil, fmt.Errorf("exactly one outbound is expected, found %d", len(outs))
	}
	if outs[0].Protocol == "" {
		return nil, errors.New("outbound has no protocol")
	}
	o, err := outs[0].Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build conf: %s", err)
	}
	return o, nil
}

// probeCallTimeout is enough for every attempt of the request with the
// largest defaults the server may apply.
func probeCallTimeout(req *observatoryService.ProbeOutboundRequest) time.Duration {
	n := time.Duration(req.Samples)
	if n == 0 {
		n = 3
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	interval := time.Duration(req.IntervalMs) * time.Millisecond
	if interval == 0 {
		interval = 200 * time.Millisecond
	}
	total := n*(timeout+interval) + 10*time.Second
	if total > 130*time.Second {
		total = 130 * time.Second
	}
	return total
}

type probeJSONSample struct {
	Ok         bool   `json:"ok"`
	RttMs      *int64 `json:"rttMs,omitempty"`
	HttpStatus int32  `json:"httpStatus,omitempty"`
	Error      string `json:"error,omitempty"`
}

type probeJSONResult struct {
	Tag         string            `json:"tag"`
	Destination string            `json:"destination"`
	Method      string            `json:"method"`
	Samples     []probeJSONSample `json:"samples"`
	Warnings    []string          `json:"warnings,omitempty"`
}

// probeJSON is the -json output of "api probe"; its format is fixed.
func probeJSON(resp *observatoryService.ProbeOutboundResponse) ([]byte, error) {
	r := probeJSONResult{
		Tag:         resp.GetTag(),
		Destination: resp.GetDestination(),
		Method:      resp.GetMethod(),
		Samples:     []probeJSONSample{},
		Warnings:    resp.GetWarnings(),
	}
	for _, s := range resp.GetSamples() {
		js := probeJSONSample{Ok: s.GetOk(), HttpStatus: s.GetHttpStatus(), Error: s.GetError()}
		if s.GetOk() {
			rtt := s.GetRttMs()
			js.RttMs = &rtt
		}
		r.Samples = append(r.Samples, js)
	}
	return json.Marshal(r)
}

// probeText is the readable output of "api probe".
func probeText(resp *observatoryService.ProbeOutboundResponse) string {
	var b strings.Builder
	name := resp.GetTag()
	if name == "" {
		name = "(new outbound)"
	}
	fmt.Fprintf(&b, "%s: %s %s\n", name, resp.GetMethod(), resp.GetDestination())
	ok := 0
	for i, s := range resp.GetSamples() {
		if s.GetOk() {
			ok++
			fmt.Fprintf(&b, "  %2d  ok    %6d ms  HTTP %d\n", i+1, s.GetRttMs(), s.GetHttpStatus())
		} else {
			fmt.Fprintf(&b, "  %2d  fail  %s\n", i+1, s.GetError())
		}
	}
	fmt.Fprintf(&b, "%d of %d answered\n", ok, len(resp.GetSamples()))
	for _, w := range resp.GetWarnings() {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return b.String()
}

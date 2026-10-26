package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pelletier/go-toml"
	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
	json_reader "github.com/xtls/xray-core/infra/conf/json"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/main/confloader"
)

const defaultCheckConfDir = "/etc/xray/conf.d"

var cmdCheck = &base.Command{
	UsageLine:   "{{.Exec}} check [-c config.json] [-confdir dir] [-format fmt] [-list file] [--set path=value]... <tag> [<ip>] <count> <interval>",
	Short:       "Check health of an outbound",
	CustomFlags: true,
	Long: `
Check an outbound with the xray health check (burstObservatory),
connecting to <ip> instead of the address in its config.

	{{.Exec}} check cf_22 10.10.10.10 3 1
	{{.Exec}} check -list=ips.txt cf_22 3 1

Arguments:
	<tag>       outbound tag taken as the base config (cf_22)
	<ip>        address to connect to instead of the configured one
	            (omit when -list is used)
	<count>     number of checks
	<interval>  seconds between checks, may be fractional (0.5)

The -list=file flag checks every IP from the file, one per line.
Empty lines and lines starting with # are skipped.

Config: -config=file, -c=file, -confdir=dir and -format=fmt work
as in "run". If none of -c and -confdir is given, the default
-confdir ` + defaultCheckConfDir + ` is used.

The config must contain burstObservatory with pingConfig (its
destination, timeout and httpMethod are used). Inbounds, routing,
api and metrics are not started, so a running xray is not affected.
TLS serverName and xhttp host stay as configured.

The --set path=value flag overrides one more field of the checked
outbound. The path is dot-separated from the outbound root,
array indexes are numbers (settings.vnext.0.address). The value
is parsed as JSON, or used as a string otherwise. Can be repeated.

Prints one line per IP:
	alive: <bool>, delay: <ms>, outbound_tag: "<tag>"
delay is the minimal time of successful checks, alive is false
if any check failed. With -list, ', ip: "<ip>"' is appended.
	`,
}

func init() {
	cmdCheck.Run = executeCheck
}

type setFlags []string

func (s *setFlags) String() string     { return strings.Join(*s, ",") }
func (s *setFlags) Set(v string) error { *s = append(*s, v); return nil }

func executeCheck(cmd *base.Command, args []string) {
	if err := runCheck(args); err != nil {
		fmt.Fprintln(os.Stderr, "check failed:", err)
		os.Exit(1)
	}
}

func runCheck(args []string) error {
	var sets setFlags
	var listFile string
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.Var(&configFiles, "config", "Config path for Xray.")
	fs.Var(&configFiles, "c", "Short alias of -config")
	fs.StringVar(&configDir, "confdir", "", "A dir with multiple json config")
	fs.StringVar(format, "format", "auto", "Format of input file.")
	fs.Var(&sets, "set", "Override outbound field: path=value")
	fs.StringVar(&listFile, "list", "", "File with IPs to check, one per line")

	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	want := 4
	if listFile != "" {
		want = 3
	}
	if len(positional) != want {
		return fmt.Errorf("expected %d arguments, got %d; usage: check <tag> <ip> <count> <interval> or check -list=file <tag> <count> <interval>", want, len(positional))
	}
	tag, rest := positional[0], positional[1:]
	var ips []string
	if listFile == "" {
		ips, rest = rest[:1], rest[1:]
	} else {
		var err error
		if ips, err = readIPList(listFile); err != nil {
			return err
		}
	}
	count, err := strconv.Atoi(rest[0])
	if err != nil || count < 1 {
		return fmt.Errorf("invalid count %q: positive integer expected", rest[0])
	}
	sec, err := strconv.ParseFloat(rest[1], 64)
	if err != nil || sec < 0 {
		return fmt.Errorf("invalid interval %q: seconds expected", rest[1])
	}
	interval := time.Duration(sec * float64(time.Second))

	if len(configFiles) == 0 && configDir == "" {
		configDir = defaultCheckConfDir
	}
	files := getConfigFilePath(false)
	// do not read or overwrite the saved results of a running xray
	burst.DisablePersistence = true

	var failed int
	for _, ip := range ips {
		line, err := checkOne(files, tag, ip, sets, count, interval)
		if err != nil {
			if listFile == "" {
				return err
			}
			fmt.Fprintf(os.Stderr, "check failed for %s: %v\n", ip, err)
			failed++
			continue
		}
		if listFile != "" {
			line += fmt.Sprintf(", ip: %q", ip)
		}
		fmt.Println(line)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks could not run", failed, len(ips))
	}
	return nil
}

func readIPList(file string) ([]string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read list: %w", err)
	}
	var ips []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			ips = append(ips, l)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs in %s", file)
	}
	return ips, nil
}

// checkOne runs count xray health checks of tag connecting to ip and
// returns the result line.
func checkOne(files []string, tag, ip string, sets []string, count int, interval time.Duration) (string, error) {
	cfg, err := loadCheckConfig(files, tag, ip, sets, count)
	if err != nil {
		return "", err
	}

	server, err := core.New(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to create server: %w", err)
	}
	if err := server.Start(); err != nil {
		return "", fmt.Errorf("failed to start: %w", err)
	}
	defer server.Close()

	obs, ok := server.GetFeature(extension.ObservatoryType()).(extension.BurstObservatory)
	if !ok {
		return "", fmt.Errorf("burstObservatory is not running")
	}

	// one-time xray health checks, the same as the balancer uses
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(interval)
		}
		obs.Check([]string{tag})
	}

	msg, err := obs.GetObservation(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to get observation: %w", err)
	}
	var hp *observatory.HealthPingMeasurementResult
	for _, s := range msg.(*observatory.ObservationResult).Status {
		if s.OutboundTag == tag {
			hp = s.HealthPing
			break
		}
	}
	alive, delay := false, int64(0)
	if hp != nil && hp.All > 0 {
		alive = hp.Fail == 0
		if hp.All > hp.Fail {
			delay = time.Duration(hp.Min).Milliseconds()
		}
	}
	return fmt.Sprintf("alive: %t, delay: %d, outbound_tag: %q", alive, delay, tag), nil
}

// addressPath returns the --set path of the server address in an outbound.
func addressPath(outbound any) string {
	settings, _ := outbound.(map[string]any)["settings"].(map[string]any)
	for _, list := range []string{"vnext", "servers"} {
		if arr, ok := settings[list].([]any); ok && len(arr) > 0 {
			return "settings." + list + ".0.address"
		}
	}
	return "settings.address"
}

func loadCheckConfig(files []string, tag, ip string, sets []string, count int) (*core.Config, error) {
	docs := make([]map[string]any, len(files))
	target := -1
	for i, file := range files {
		f := getConfigFormat()
		if f == "auto" {
			f = "json"
			if file != "stdin:" {
				f = core.GetFormat(file)
			}
		}
		data, err := readConfigAsJSON(file, f)
		if err != nil {
			return nil, fmt.Errorf("failed to load config %s: %w", file, err)
		}
		if err := decodeJSONNumber(data, &docs[i]); err != nil {
			return nil, fmt.Errorf("failed to load config %s: %w", file, err)
		}
		if outboundIndex(docs[i], tag) >= 0 {
			target = i
		}
	}
	if target < 0 {
		return nil, fmt.Errorf("outbound with tag %q not found", tag)
	}

	outbounds := docs[target]["outbounds"].([]any)
	idx := outboundIndex(docs[target], tag)
	sets = append([]string{addressPath(outbounds[idx]) + "=" + ip}, sets...)
	for _, s := range sets {
		path, raw, ok := strings.Cut(s, "=")
		if !ok || path == "" {
			return nil, fmt.Errorf("invalid --set %q: expected path=value", s)
		}
		var value any
		if err := decodeJSONNumber([]byte(raw), &value); err != nil {
			value = raw
		}
		updated, err := setPath(outbounds[idx], strings.Split(path, "."), value)
		if err != nil {
			return nil, fmt.Errorf("invalid --set %q: %w", s, err)
		}
		outbounds[idx] = updated
	}

	merged := &conf.Config{}
	for i, doc := range docs {
		data, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		c, err := serial.DecodeJSONConfig(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to load config %s: %w", files[i], err)
		}
		if i == 0 {
			*merged = *c
		} else {
			merged.Override(c, files[i])
		}
	}

	bo := merged.BurstObservatory
	if bo == nil {
		return nil, fmt.Errorf("burstObservatory is not configured")
	}
	if bo.HealthCheck == nil {
		return nil, fmt.Errorf("burstObservatory.pingConfig is not configured")
	}
	// observe only this outbound, keep all count results, and keep the
	// scheduled rounds out of the way: checks are run by checkOne
	bo.SubjectSelector = []string{tag}
	bo.HealthCheck.SamplingCount = count
	bo.HealthCheck.Interval = duration.Duration(time.Hour)

	// do not start listeners and routing of the running config
	merged.InboundConfigs = nil
	merged.RouterConfig = nil
	merged.API = nil
	merged.Metrics = nil
	merged.Observatory = nil

	cfg, err := merged.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %w", err)
	}
	return cfg, nil
}

func readConfigAsJSON(file, format string) ([]byte, error) {
	r, err := confloader.LoadConfig(file)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	switch format {
	case "json":
		return io.ReadAll(&json_reader.Reader{Reader: bytes.NewReader(data)})
	case "yaml":
		return yaml.YAMLToJSON(data)
	case "toml":
		m := make(map[string]any)
		if err := toml.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		return json.Marshal(m)
	}
	return nil, fmt.Errorf("unsupported config format %q", format)
}

func outboundIndex(doc map[string]any, tag string) int {
	outbounds, _ := doc["outbounds"].([]any)
	for i, o := range outbounds {
		if m, ok := o.(map[string]any); ok && m["tag"] == tag {
			return i
		}
	}
	return -1
}

func decodeJSONNumber(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing data")
	}
	return nil
}

func setPath(node any, parts []string, value any) (any, error) {
	if len(parts) == 0 {
		return value, nil
	}
	key := parts[0]
	if key == "" {
		return nil, fmt.Errorf("empty path segment")
	}
	switch n := node.(type) {
	case nil:
		child, err := setPath(nil, parts[1:], value)
		if err != nil {
			return nil, err
		}
		return map[string]any{key: child}, nil
	case map[string]any:
		child, err := setPath(n[key], parts[1:], value)
		if err != nil {
			return nil, err
		}
		n[key] = child
		return n, nil
	case []any:
		i, err := strconv.Atoi(key)
		if err != nil {
			return nil, fmt.Errorf("%q is not an array index", key)
		}
		if i < 0 || i >= len(n) {
			return nil, fmt.Errorf("index %d out of range (len %d)", i, len(n))
		}
		child, err := setPath(n[i], parts[1:], value)
		if err != nil {
			return nil, err
		}
		n[i] = child
		return n, nil
	default:
		return nil, fmt.Errorf("cannot descend into %q: not an object or array", key)
	}
}

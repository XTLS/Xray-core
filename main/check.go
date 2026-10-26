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

const defaultCheckConfDir = "/usr/local/etc/xray"

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

Config: -config=file (-c=file) and -confdir=dir select the config
as in "run"; -format=fmt sets its format. If none of -c and -confdir
is given, -confdir ` + defaultCheckConfDir + ` is used. A config dir may
hold one file (config.json) or a config split into several files
(00_log.json, 01_api.json, ...): all *.json, *.jsonc, *.toml, *.yaml
and *.yml files of the dir are merged in name order, as "run" does.
The config is never read from stdin. Loaded files are printed to
stderr.

The config must contain burstObservatory with pingConfig (its
destination, timeout and httpMethod are used). Only the checked
outbound and the outbounds it connects through (dialerProxy,
proxySettings) are started; inbounds, routing, api, metrics, dns,
fakedns, geodata and reverse are not, so it starts fast and a running
xray is not affected. TLS serverName and xhttp host stay as
configured. Only the checks below are run: no observatory rounds and
no saved results are used.

Progress goes to stderr: loaded config files, started outbounds and
the ping timeout, then "check i/n: ok|failed in <time>" per check.

The --set path=value flag overrides one more field of the checked
outbound. The path is dot-separated from the outbound root,
array indexes are numbers (settings.vnext.0.address). The value
is parsed as JSON, or used as a string otherwise. Can be repeated.

To reset the results a running xray keeps for an outbound or a
tag prefix, see "{{.Exec}} help api obsreset".

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

	files, err := checkConfigFiles()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "config:", strings.Join(files, ", "))
	// do not read or overwrite the saved results of a running xray, and
	// run only the checks below, without observatory's own rounds
	burst.DisablePersistence = true
	burst.DisableScheduler = true

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

// checkConfigFiles returns the config files for check: -c files and the
// files of -confdir, or of defaultCheckConfDir when neither is given.
// Unlike "run" it never falls back to stdin.
func checkConfigFiles() ([]string, error) {
	if len(configFiles) == 0 && configDir == "" {
		configDir = defaultCheckConfDir
	}
	if configDir != "" {
		if !dirExists(configDir) {
			return nil, fmt.Errorf("config dir %s not found, use -c file or -confdir dir", configDir)
		}
		readConfDir(configDir)
	}
	if len(configFiles) == 0 {
		return nil, fmt.Errorf("no config files (*.json, *.jsonc, *.toml, *.yaml, *.yml) in %s, use -c file or -confdir dir", configDir)
	}
	return configFiles, nil
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
// returns the result line. Progress goes to stderr.
func checkOne(files []string, tag, ip string, sets []string, count int, interval time.Duration) (string, error) {
	cfg, info, err := loadCheckConfig(files, tag, ip, sets, count)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "%s: starting xray, %s\n", ip, info)

	server, err := core.New(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to create server: %w", err)
	}
	if err := server.Start(); err != nil {
		return "", fmt.Errorf("failed to start: %w", err)
	}
	defer closeWithTimeout(server, 3*time.Second)

	obs, ok := server.GetFeature(extension.ObservatoryType()).(extension.BurstObservatory)
	if !ok {
		return "", fmt.Errorf("burstObservatory is not running")
	}

	// one-time xray health checks, the same as the balancer uses
	var hp *observatory.HealthPingMeasurementResult
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(interval)
		}
		start := time.Now()
		obs.Check([]string{tag})
		prev := hp
		if hp, err = healthOf(obs, tag); err != nil {
			return "", err
		}
		state := "ok"
		switch {
		case hp == nil || (prev != nil && hp.All == prev.All):
			state = "no result (network down?)"
		case prev == nil && hp.Fail > 0, prev != nil && hp.Fail > prev.Fail:
			state = "failed"
		}
		fmt.Fprintf(os.Stderr, "%s: check %d/%d: %s in %v\n", ip, i+1, count, state, time.Since(start).Round(time.Millisecond))
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

// healthOf returns the health results of tag, nil if there are none yet.
func healthOf(obs extension.Observatory, tag string) (*observatory.HealthPingMeasurementResult, error) {
	msg, err := obs.GetObservation(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get observation: %w", err)
	}
	for _, s := range msg.(*observatory.ObservationResult).Status {
		if s.OutboundTag == tag {
			return s.HealthPing, nil
		}
	}
	return nil, nil
}

// closeWithTimeout closes the instance, but does not wait longer than d:
// the result is already known and pending connections must not hold it.
func closeWithTimeout(server *core.Instance, d time.Duration) {
	done := make(chan struct{})
	go func() {
		server.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		fmt.Fprintf(os.Stderr, "xray instance did not close in %v, continuing\n", d)
	}
}

// outboundRefs returns tags of outbounds an outbound uses to connect:
// every sockopt.dialerProxy (also inside xhttp downloadSettings) and
// proxySettings.tag.
func outboundRefs(node any) []string {
	var refs []string
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "dialerProxy" {
				if t, ok := v.(string); ok && t != "" {
					refs = append(refs, t)
				}
			}
			if k == "proxySettings" {
				if m, ok := v.(map[string]any); ok {
					if t, ok := m["tag"].(string); ok && t != "" {
						refs = append(refs, t)
					}
				}
			}
			refs = append(refs, outboundRefs(v)...)
		}
	case []any:
		for _, v := range n {
			refs = append(refs, outboundRefs(v)...)
		}
	}
	return refs
}

// keepOutbounds leaves in docs only the outbound tag and the outbounds it
// depends on (dialerProxy chains), and returns their tags in config order.
func keepOutbounds(docs []map[string]any, tag string) ([]string, error) {
	byTag := map[string]any{}
	for _, doc := range docs {
		outbounds, _ := doc["outbounds"].([]any)
		for _, o := range outbounds {
			if m, ok := o.(map[string]any); ok {
				if t, ok := m["tag"].(string); ok {
					byTag[t] = o
				}
			}
		}
	}
	need := map[string]bool{tag: true}
	queue := []string{tag}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, ref := range outboundRefs(byTag[cur]) {
			if need[ref] {
				continue
			}
			if _, ok := byTag[ref]; !ok {
				return nil, fmt.Errorf("outbound %q used by %q (dialerProxy/proxySettings) not found", ref, cur)
			}
			need[ref] = true
			queue = append(queue, ref)
		}
	}
	var kept []string
	for _, doc := range docs {
		outbounds, ok := doc["outbounds"].([]any)
		if !ok {
			continue
		}
		filtered := []any{}
		for _, o := range outbounds {
			if m, ok := o.(map[string]any); ok {
				if t, ok := m["tag"].(string); ok && need[t] {
					filtered = append(filtered, o)
					kept = append(kept, t)
				}
			}
		}
		doc["outbounds"] = filtered
	}
	return kept, nil
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

// loadCheckConfig builds a minimal config: the outbound tag (with ip as its
// address) and its dialerProxy chain, burstObservatory for that tag only,
// and none of inbounds, routing, api, metrics, dns, fakedns, geodata and
// reverse. info describes it for the progress output.
func loadCheckConfig(files []string, tag, ip string, sets []string, count int) (cfg *core.Config, info string, err error) {
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
			return nil, "", fmt.Errorf("failed to load config %s: %w", file, err)
		}
		if err := decodeJSONNumber(data, &docs[i]); err != nil {
			return nil, "", fmt.Errorf("failed to load config %s: %w", file, err)
		}
		if outboundIndex(docs[i], tag) >= 0 {
			target = i
		}
	}
	if target < 0 {
		return nil, "", fmt.Errorf("outbound with tag %q not found", tag)
	}

	outbounds := docs[target]["outbounds"].([]any)
	idx := outboundIndex(docs[target], tag)
	sets = append([]string{addressPath(outbounds[idx]) + "=" + ip}, sets...)
	for _, s := range sets {
		path, raw, ok := strings.Cut(s, "=")
		if !ok || path == "" {
			return nil, "", fmt.Errorf("invalid --set %q: expected path=value", s)
		}
		var value any
		if err := decodeJSONNumber([]byte(raw), &value); err != nil {
			value = raw
		}
		updated, err := setPath(outbounds[idx], strings.Split(path, "."), value)
		if err != nil {
			return nil, "", fmt.Errorf("invalid --set %q: %w", s, err)
		}
		outbounds[idx] = updated
	}

	kept, err := keepOutbounds(docs, tag)
	if err != nil {
		return nil, "", err
	}

	merged := &conf.Config{}
	for i, doc := range docs {
		data, err := json.Marshal(doc)
		if err != nil {
			return nil, "", err
		}
		c, err := serial.DecodeJSONConfig(bytes.NewReader(data))
		if err != nil {
			return nil, "", fmt.Errorf("failed to load config %s: %w", files[i], err)
		}
		if i == 0 {
			*merged = *c
		} else {
			merged.Override(c, files[i])
		}
	}

	bo := merged.BurstObservatory
	if bo == nil {
		return nil, "", fmt.Errorf("burstObservatory is not configured")
	}
	if bo.HealthCheck == nil {
		return nil, "", fmt.Errorf("burstObservatory.pingConfig is not configured")
	}
	// observe only this outbound, keep all count results, and keep the
	// scheduled rounds out of the way: checks are run by checkOne
	bo.SubjectSelector = []string{tag}
	bo.HealthCheck.SamplingCount = count
	bo.HealthCheck.Interval = duration.Duration(time.Hour)

	timeout := time.Duration(bo.HealthCheck.Timeout)
	if timeout <= 0 {
		timeout = 5 * time.Second // burst default
	}

	// nothing of the running config but the checked outbound: no
	// listeners, routing, api, metrics, dns, fakedns, geodata, reverse
	merged.InboundConfigs = nil
	merged.RouterConfig = nil
	merged.API = nil
	merged.Metrics = nil
	merged.Observatory = nil
	merged.DNSConfig = nil
	merged.FakeDNS = nil
	merged.Geodata = nil
	merged.Reverse = nil

	cfg, err = merged.Build()
	if err != nil {
		return nil, "", fmt.Errorf("failed to build config: %w", err)
	}
	return cfg, fmt.Sprintf("outbounds: %s, timeout %v", strings.Join(kept, ", "), timeout), nil
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

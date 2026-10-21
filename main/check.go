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
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/infra/conf"
	json_reader "github.com/xtls/xray-core/infra/conf/json"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/main/confloader"
)

var cmdCheck = &base.Command{
	UsageLine:   "{{.Exec}} check [-c config.json] [-confdir dir] [-format fmt] [--set path=value]... <tag>",
	Short:       "Check health of an outbound",
	CustomFlags: true,
	Long: `
Check health of a single outbound using burstObservatory.

The config must contain burstObservatory whose subjectSelector
covers <tag>, and an outbound with that tag.

The -config=file, -c=file, -confdir=dir and -format=fmt flags
select the config, as in "run".

The --set path=value flag overrides a field of the checked
outbound. The path is dot-separated from the outbound root,
array indexes are numbers (settings.vnext.0.address). The value
is parsed as JSON, or used as a string otherwise. Can be repeated.

Prints "alive: <bool>, delay: <ms>, outbound_tag: "<tag>"" as
the last line of stdout once pingConfig.sampling results have
been collected for the outbound.
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
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.Var(&configFiles, "config", "Config path for Xray.")
	fs.Var(&configFiles, "c", "Short alias of -config")
	fs.StringVar(&configDir, "confdir", "", "A dir with multiple json config")
	fs.StringVar(format, "format", "auto", "Format of input file.")
	fs.Var(&sets, "set", "Override outbound field: path=value")

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
	if len(positional) != 1 {
		return fmt.Errorf("exactly one outbound tag expected, got %d", len(positional))
	}
	tag := positional[0]

	cfg, sampling, err := loadCheckConfig(tag, sets)
	if err != nil {
		return err
	}

	server, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	obs, ok := server.GetFeature(extension.ObservatoryType()).(extension.Observatory)
	if !ok {
		server.Close()
		return fmt.Errorf("observatory is not running")
	}

	var status *observatory.OutboundStatus
	for status == nil {
		time.Sleep(200 * time.Millisecond)
		msg, err := obs.GetObservation(context.Background())
		if err != nil {
			server.Close()
			return fmt.Errorf("failed to get observation: %w", err)
		}
		for _, s := range msg.(*observatory.ObservationResult).Status {
			if s.OutboundTag == tag && s.HealthPing != nil && s.HealthPing.All >= sampling {
				status = s
				break
			}
		}
	}
	server.Close()

	hp := status.HealthPing
	alive := hp.Fail == 0
	delay := int64(0)
	if hp.All > hp.Fail {
		delay = time.Duration(hp.Average).Milliseconds()
	}
	fmt.Printf("\nalive: %t, delay: %d, outbound_tag: %q\n", alive, delay, tag)
	return nil
}

func loadCheckConfig(tag string, sets []string) (*core.Config, int64, error) {
	files := getConfigFilePath(false)
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
			return nil, 0, fmt.Errorf("failed to load config %s: %w", file, err)
		}
		if err := decodeJSONNumber(data, &docs[i]); err != nil {
			return nil, 0, fmt.Errorf("failed to load config %s: %w", file, err)
		}
		if outboundIndex(docs[i], tag) >= 0 {
			target = i
		}
	}
	if target < 0 {
		return nil, 0, fmt.Errorf("outbound with tag %q not found", tag)
	}

	outbounds := docs[target]["outbounds"].([]any)
	idx := outboundIndex(docs[target], tag)
	for _, s := range sets {
		path, raw, ok := strings.Cut(s, "=")
		if !ok || path == "" {
			return nil, 0, fmt.Errorf("invalid --set %q: expected path=value", s)
		}
		var value any
		if err := decodeJSONNumber([]byte(raw), &value); err != nil {
			value = raw
		}
		updated, err := setPath(outbounds[idx], strings.Split(path, "."), value)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid --set %q: %w", s, err)
		}
		outbounds[idx] = updated
	}

	merged := &conf.Config{}
	for i, doc := range docs {
		data, err := json.Marshal(doc)
		if err != nil {
			return nil, 0, err
		}
		c, err := serial.DecodeJSONConfig(bytes.NewReader(data))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to load config %s: %w", files[i], err)
		}
		if i == 0 {
			*merged = *c
		} else {
			merged.Override(c, files[i])
		}
	}

	burst := merged.BurstObservatory
	if burst == nil {
		return nil, 0, fmt.Errorf("burstObservatory is not configured")
	}
	covered := false
	for _, sel := range burst.SubjectSelector {
		if strings.HasPrefix(tag, sel) {
			covered = true
			break
		}
	}
	if !covered {
		return nil, 0, fmt.Errorf("burstObservatory.subjectSelector does not cover tag %q", tag)
	}
	sampling := int64(10)
	if burst.HealthCheck != nil && burst.HealthCheck.SamplingCount > 0 {
		sampling = int64(burst.HealthCheck.SamplingCount)
	}

	cfg, err := merged.Build()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build config: %w", err)
	}
	return cfg, sampling, nil
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

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdMasqueTelemetry = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api masque [--server=127.0.0.1:8080] [-tag outboundTag]",
	Short:       "Retrieve MASQUE telemetry",
	Long: `
Retrieve MASQUE transport telemetry from the metrics endpoint.

> Ensure that the metrics server is enabled and reachable. The command reads "/debug/vars" and extracts the "masque" section.

Arguments:

	-s, -server <server:port|url>
		The metrics HTTP server address. Default 127.0.0.1:8080
		You may also pass a full URL such as http://127.0.0.1:8080/debug/vars

	-t, -timeout <seconds>
		Timeout in seconds for fetching telemetry. Default 3

	-json
		Output JSON.

	-tag <outboundTag>
		Show only one outbound telemetry bucket.

	-only <healthy|degraded|fallback-heavy|idle>
		Show only outbound buckets with the selected verdict.

	-sort <name|score|fallback|read-fallback|write-fallback|requested|datagram-read|datagram-write>
		Sort outbound buckets in text output. Default name.

	-limit <n>
		Show only the first n outbound buckets after sorting. Default 0 means all.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
	{{.Exec}} {{.LongName}} --server=http://127.0.0.1:8080/debug/vars -tag proxy-a
	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -only fallback-heavy -sort score
	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -sort fallback -limit 5
`,
	Run: executeMasqueTelemetry,
}

type masqueTelemetrySnapshot struct {
	Global   map[string]int64            `json:"global"`
	Outbound map[string]map[string]int64 `json:"outbound"`
}

type masqueTelemetryRenderOptions struct {
	sortMode    string
	limit       int
	onlyVerdict string
}

type masqueOutboundTelemetryEntry struct {
	Key     string
	Metrics map[string]int64
}

const (
	masqueSortName          = "name"
	masqueSortScore         = "score"
	masqueSortFallback      = "fallback"
	masqueSortReadFallback  = "read-fallback"
	masqueSortWriteFallback = "write-fallback"
	masqueSortRequested     = "requested"
	masqueSortDatagramRead  = "datagram-read"
	masqueSortDatagramWrite = "datagram-write"
)

func executeMasqueTelemetry(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	tag := cmd.Flag.String("tag", "", "")
	onlyVerdict := cmd.Flag.String("only", "", "")
	sortMode := cmd.Flag.String("sort", masqueSortName, "")
	limit := cmd.Flag.Int("limit", 0, "")
	cmd.Flag.Parse(args)

	normalizedOnlyVerdict, err := normalizeMasqueTelemetryOnlyVerdict(*onlyVerdict)
	if err != nil {
		base.Fatalf("%s", err)
	}
	normalizedSortMode, err := normalizeMasqueTelemetrySortMode(*sortMode)
	if err != nil {
		base.Fatalf("%s", err)
	}
	if *limit < 0 {
		base.Fatalf("limit must be >= 0")
	}

	snapshot, err := fetchMasqueTelemetry(apiServerAddrPtr, time.Duration(apiTimeout)*time.Second)
	if err != nil {
		base.Fatalf("%s", err)
	}

	snapshot, err = filterMasqueTelemetry(snapshot, *tag)
	if err != nil {
		base.Fatalf("%s", err)
	}
	snapshot = filterMasqueTelemetryByVerdict(snapshot, normalizedOnlyVerdict)

	options := masqueTelemetryRenderOptions{
		sortMode:    normalizedSortMode,
		limit:       *limit,
		onlyVerdict: normalizedOnlyVerdict,
	}
	snapshot = limitMasqueTelemetrySnapshot(snapshot, options)

	if apiJSON {
		output, err := renderMasqueTelemetryJSON(snapshot)
		if err != nil {
			base.Fatalf("%s", err)
		}
		os.Stdout.WriteString(output)
		return
	}

	os.Stdout.WriteString(renderMasqueTelemetryText(snapshot, options))
}

func fetchMasqueTelemetry(server string, timeout time.Duration) (*masqueTelemetrySnapshot, error) {
	target, err := resolveMetricsDebugVarsURL(server)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics from %s: %w", target, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status code from %s: %d", target, resp.StatusCode)
	}

	var debugVars map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&debugVars); err != nil {
		return nil, fmt.Errorf("failed to decode debug vars from %s: %w", target, err)
	}

	raw, ok := debugVars["masque"]
	if !ok {
		return nil, errors.New(`"masque" telemetry not found in /debug/vars`)
	}

	var snapshot masqueTelemetrySnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, fmt.Errorf("failed to decode masque telemetry: %w", err)
	}
	if snapshot.Global == nil {
		snapshot.Global = map[string]int64{}
	}
	if snapshot.Outbound == nil {
		snapshot.Outbound = map[string]map[string]int64{}
	}
	return &snapshot, nil
}

func resolveMetricsDebugVarsURL(server string) (string, error) {
	target := strings.TrimSpace(server)
	if target == "" {
		return "", errors.New("metrics server address not specified")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid metrics server address %q: %w", server, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported metrics URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid metrics server address %q", server)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/debug/vars"
	}
	return parsed.String(), nil
}

func filterMasqueTelemetry(snapshot *masqueTelemetrySnapshot, tag string) (*masqueTelemetrySnapshot, error) {
	if snapshot == nil {
		return nil, errors.New("nil masque telemetry snapshot")
	}
	if tag == "" {
		return snapshot, nil
	}

	metrics, ok := snapshot.Outbound[tag]
	if !ok {
		return nil, fmt.Errorf("masque telemetry for outbound %q not found", tag)
	}

	filtered := &masqueTelemetrySnapshot{
		Global:   snapshot.Global,
		Outbound: map[string]map[string]int64{tag: metrics},
	}
	return filtered, nil
}

func renderMasqueTelemetryJSON(snapshot *masqueTelemetrySnapshot) (string, error) {
	if snapshot == nil {
		return "", nil
	}
	output, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to encode masque telemetry as JSON: %w", err)
	}
	return string(output) + "\n", nil
}

func renderMasqueTelemetryText(snapshot *masqueTelemetrySnapshot, options masqueTelemetryRenderOptions) string {
	if snapshot == nil {
		return ""
	}

	sb := new(strings.Builder)
	writeMasqueTelemetrySection(sb, "Global", snapshot.Global)

	for _, entry := range selectMasqueTelemetryOutbounds(snapshot.Outbound, options) {
		sb.WriteByte('\n')
		writeMasqueTelemetrySection(sb, formatMasqueOutboundTitle(entry, options.sortMode), masqueTelemetryDisplayMetrics(entry.Metrics))
	}

	return sb.String()
}

func writeMasqueTelemetrySection(sb *strings.Builder, title string, metrics map[string]int64) {
	sb.WriteString(title)
	sb.WriteString(":\n")
	for _, key := range sortedMetricKeys(metrics) {
		sb.WriteString("  ")
		sb.WriteString(key)
		sb.WriteString(": ")
		sb.WriteString(fmt.Sprintf("%d", metrics[key]))
		sb.WriteByte('\n')
	}
}

func sortedTelemetryKeys(values map[string]map[string]int64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedMetricKeys(values map[string]int64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func normalizeMasqueTelemetrySortMode(mode string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(mode))
	if normalized == "" {
		return masqueSortName, nil
	}
	switch normalized {
	case masqueSortName,
		masqueSortScore,
		masqueSortFallback,
		masqueSortReadFallback,
		masqueSortWriteFallback,
		masqueSortRequested,
		masqueSortDatagramRead,
		masqueSortDatagramWrite:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported sort mode %q", mode)
	}
}

func normalizeMasqueTelemetryOnlyVerdict(verdict string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(verdict))
	if normalized == "" {
		return "", nil
	}
	switch normalized {
	case "healthy", "degraded", "fallback-heavy", "idle":
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported verdict filter %q", verdict)
	}
}

func filterMasqueTelemetryByVerdict(snapshot *masqueTelemetrySnapshot, verdict string) *masqueTelemetrySnapshot {
	if snapshot == nil || verdict == "" {
		return snapshot
	}

	filtered := &masqueTelemetrySnapshot{
		Global:   snapshot.Global,
		Outbound: map[string]map[string]int64{},
	}
	for key, metrics := range snapshot.Outbound {
		if masqueTelemetryVerdict(metrics) == verdict {
			filtered.Outbound[key] = metrics
		}
	}
	return filtered
}

func limitMasqueTelemetrySnapshot(snapshot *masqueTelemetrySnapshot, options masqueTelemetryRenderOptions) *masqueTelemetrySnapshot {
	if snapshot == nil {
		return nil
	}
	selected := selectMasqueTelemetryOutbounds(snapshot.Outbound, options)
	outbound := make(map[string]map[string]int64, len(selected))
	for _, entry := range selected {
		outbound[entry.Key] = entry.Metrics
	}
	return &masqueTelemetrySnapshot{
		Global:   snapshot.Global,
		Outbound: outbound,
	}
}

func selectMasqueTelemetryOutbounds(values map[string]map[string]int64, options masqueTelemetryRenderOptions) []masqueOutboundTelemetryEntry {
	entries := make([]masqueOutboundTelemetryEntry, 0, len(values))
	for key, metrics := range values {
		entries = append(entries, masqueOutboundTelemetryEntry{
			Key:     key,
			Metrics: metrics,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if options.sortMode == masqueSortName {
			return entries[i].Key < entries[j].Key
		}
		left := masqueTelemetrySortValue(entries[i].Metrics, options.sortMode)
		right := masqueTelemetrySortValue(entries[j].Metrics, options.sortMode)
		if left != right {
			if options.sortMode == masqueSortScore {
				return left < right
			}
			return left > right
		}
		return entries[i].Key < entries[j].Key
	})

	if options.limit > 0 && len(entries) > options.limit {
		entries = entries[:options.limit]
	}
	return entries
}

func masqueTelemetrySortValue(metrics map[string]int64, sortMode string) int64 {
	switch sortMode {
	case masqueSortScore:
		return masqueTelemetryHealthScore(metrics)
	case masqueSortFallback:
		return masqueTelemetryFallbackTotal(metrics)
	case masqueSortReadFallback:
		return metrics["read_fallback_sessions"]
	case masqueSortWriteFallback:
		return metrics["write_fallback_sessions"]
	case masqueSortRequested:
		return metrics["requested_sessions"]
	case masqueSortDatagramRead:
		return metrics["datagram_read_packets"]
	case masqueSortDatagramWrite:
		return metrics["datagram_write_packets"]
	default:
		return 0
	}
}

func formatMasqueOutboundTitle(entry masqueOutboundTelemetryEntry, sortMode string) string {
	verdict := masqueTelemetryVerdict(entry.Metrics)
	if sortMode == masqueSortName {
		return fmt.Sprintf("Outbound %s [%s]", entry.Key, verdict)
	}
	return fmt.Sprintf("Outbound %s [%s=%d %s]", entry.Key, sortMode, masqueTelemetrySortValue(entry.Metrics, sortMode), verdict)
}

func masqueTelemetryDisplayMetrics(metrics map[string]int64) map[string]int64 {
	display := make(map[string]int64, len(metrics)+2)
	for key, value := range metrics {
		display[key] = value
	}
	display["fallback_total"] = masqueTelemetryFallbackTotal(metrics)
	display["health_score"] = masqueTelemetryHealthScore(metrics)
	return display
}

func masqueTelemetryFallbackTotal(metrics map[string]int64) int64 {
	return metrics["read_fallback_sessions"] + metrics["write_fallback_sessions"]
}

func masqueTelemetryHealthScore(metrics map[string]int64) int64 {
	requested := metrics["requested_sessions"]
	if requested <= 0 {
		return 100
	}

	directionalCapacity := requested * 2
	fallbackPercent := minInt64(100, masqueTelemetryFallbackTotal(metrics)*100/directionalCapacity)
	bidirectionalPercent := minInt64(100, metrics["bidirectional_datagram_sessions"]*100/requested)
	missingBidirectionalPercent := 100 - bidirectionalPercent

	score := int64(100)
	score -= (fallbackPercent * 80) / 100
	score -= (missingBidirectionalPercent * 20) / 100
	return clampInt64(score, 0, 100)
}

func masqueTelemetryVerdict(metrics map[string]int64) string {
	requested := metrics["requested_sessions"]
	if requested <= 0 {
		return "idle"
	}

	fallbackTotal := masqueTelemetryFallbackTotal(metrics)
	directionalCapacity := requested * 2
	fallbackPercent := int64(0)
	if directionalCapacity > 0 {
		fallbackPercent = minInt64(100, fallbackTotal*100/directionalCapacity)
	}

	score := masqueTelemetryHealthScore(metrics)
	switch {
	case fallbackPercent >= 50 || score < 60:
		return "fallback-heavy"
	case fallbackTotal > 0 || score < 95:
		return "degraded"
	default:
		return "healthy"
	}
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func clampInt64(v, minValue, maxValue int64) int64 {
	if v < minValue {
		return minValue
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

package burst

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	persistFileName = "burst-observatory.json"
	persistInterval = 300 * time.Second
)

// DisablePersistence turns off saving and restoring observatory results.
// Set by "xray check", so it never mixes in or overwrites the state file
// of a running xray.
var DisablePersistence bool

type persistSample struct {
	Time int64 `json:"time"` // unix nanoseconds
	RTT  int64 `json:"rtt"`  // nanoseconds
}

type persistOutbound struct {
	Samples []persistSample `json:"samples"`
}

type persistData struct {
	Observatory map[string]*persistOutbound `json:"observatory"`
}

// persistPath returns the state file path, or "" if the temp dir is unusable.
func persistPath(ctx context.Context) string {
	dir := os.TempDir()
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		errors.LogWarning(ctx, "burst observatory: temp directory ", dir, " is not available, observatory data will not be persisted")
		return ""
	}
	path := filepath.Join(dir, persistFileName)
	errors.LogInfo(ctx, "burst observatory: using ", path, " to save and restore observatory data")
	return path
}

// samples returns stored rtts in chronological order.
func (h *HealthPingRTTS) samples() []persistSample {
	var out []persistSample
	for _, r := range h.rtts {
		if r.value == rttUntested || r.time.IsZero() {
			continue
		}
		out = append(out, persistSample{Time: r.time.UnixNano(), RTT: int64(r.value)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time < out[j].Time })
	return out
}

// saveResults atomically writes current results to path.
func (h *HealthPing) saveResults(path string) {
	data := persistData{Observatory: map[string]*persistOutbound{}}
	h.access.Lock()
	for tag, r := range h.Results {
		if s := r.samples(); len(s) > 0 {
			data.Observatory[tag] = &persistOutbound{Samples: s}
		}
	}
	h.access.Unlock()

	b, err := json.MarshalIndent(&data, "", "  ")
	if err != nil {
		errors.LogWarning(h.ctx, "burst observatory: failed to encode data: ", err)
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), persistFileName+".*.tmp")
	if err != nil {
		errors.LogWarning(h.ctx, "burst observatory: failed to create temp file: ", err)
		return
	}
	_, err = tmp.Write(b)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
		errors.LogWarning(h.ctx, "burst observatory: failed to save data to ", path, ": ", err)
		return
	}
	errors.LogInfo(h.ctx, "burst observatory: saved data of ", len(data.Observatory), " outbounds to ", path)
}

// restoreResults loads results from path, ignoring outbounds not in tags.
func (h *HealthPing) restoreResults(path string, tags []string) {
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			errors.LogWarning(h.ctx, "burst observatory: failed to read ", path, ": ", err)
		}
		return
	}
	var data persistData
	if err := json.Unmarshal(b, &data); err != nil {
		errors.LogWarning(h.ctx, "burst observatory: failed to parse ", path, ": ", err)
		return
	}
	restored := 0
	for _, tag := range tags {
		o, ok := data.Observatory[tag]
		if !ok || o == nil {
			continue
		}
		sort.Slice(o.Samples, func(i, j int) bool { return o.Samples[i].Time < o.Samples[j].Time })
		for _, s := range o.Samples {
			h.restoreSample(tag, time.Duration(s.RTT), time.Unix(0, s.Time))
		}
		restored++
	}
	errors.LogInfo(h.ctx, "burst observatory: restored data of ", restored, " outbounds from ", path)
}

// restoreSample puts a sample and replaces its timestamp with the saved one.
// Called before the scheduler starts, so no concurrent Put can happen in between.
func (h *HealthPing) restoreSample(tag string, rtt time.Duration, at time.Time) {
	h.PutResult(tag, rtt)
	h.access.Lock()
	defer h.access.Unlock()
	r := h.Results[tag]
	r.rtts[r.idx].time = at
}

// startPersistence restores saved data and saves it periodically until ctx is done.
func (h *HealthPing) startPersistence(selector func() ([]string, error)) {
	if DisablePersistence {
		return
	}
	path := persistPath(h.ctx)
	if path == "" {
		return
	}
	h.persistPath = path
	if tags, err := selector(); err == nil {
		h.restoreResults(path, tags)
	} else {
		errors.LogWarning(h.ctx, "burst observatory: error select outbounds for restore: ", err)
	}
	go func() {
		ticker := time.NewTicker(persistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.saveResults(path)
			case <-h.ctx.Done():
				return
			}
		}
	}()
}

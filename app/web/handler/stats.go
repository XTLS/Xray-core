package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/julienschmidt/httprouter"
	statsCmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/app/web/client"
)

var boot time.Time

func init() {
	boot = time.Now()
}

// Garbage ↓
func GetSysStatsHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)

	uptime := time.Since(boot)
	response := &statsCmd.SysStatsResponse{
		Uptime:       uint32(uptime.Seconds()),
		NumGoroutine: uint32(runtime.NumGoroutine()),
		Alloc:        rtm.Alloc,
		TotalAlloc:   rtm.TotalAlloc,
		Sys:          rtm.Sys,
		Mallocs:      rtm.Mallocs,
		Frees:        rtm.Frees,
		LiveObjects:  rtm.Mallocs - rtm.Frees,
		NumGC:        rtm.NumGC,
		PauseTotalNs: rtm.PauseTotalNs,
	}
	ret, err := json.Marshal(response)
	if err != nil {
		newError(err)
	} else {
		fmt.Fprintf(w, "%s\n", string(ret))
	}
}

func GetStatsHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	data := ps.ByName("name")
	_, value := client.Client.GetStats(data, false)
	fmt.Fprintf(w, "%s\n", fmt.Sprintf("%v", value))
}

func QueryStatsHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	data := ps.ByName("pattern")
	pattern := client.Client.QueryStats(data, false)
	sub := make(map[string]interface{})
	for key, val := range pattern {
		sub[key] = val
	}
	var stat []map[string]interface{}
	stat = append(stat, sub)

	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)

	err := enc.Encode(&stat)
	if err != nil {
		newError("failed to convert json")
		return
	}
	//working
	fmt.Fprintf(w, "%s\n", buf.String())
}

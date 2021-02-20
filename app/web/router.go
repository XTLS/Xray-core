package web

import (
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/xtls/xray-core/app/web/handler"
	"github.com/xtls/xray-core/common/log"
)

func Default(config *WebHandler) *httprouter.Router {
	router := httprouter.New()

	router.GET("/api/xray/statssys", handler.GetSysStatsHandler)
	router.GET("/api/xray/statsquery", handler.QueryStatsHandler)
	router.GET("/api/xray/statsquery/:pattern", handler.QueryStatsHandler)
	router.GET("/api/xray/stats", handler.GetStatsHandler)
	router.GET("/api/xray/stats/:name", handler.GetStatsHandler)
	router.GET("/api/xray/inbound/remove/:tag", handler.RemoveInboundHandler)
	router.POST("/api/xray/inbound/add", handler.AddInboundHandler)
	router.GET("/api/xray/outbound/remove/:tag", handler.RemoveOutboundHandler)
	router.POST("/api/xray/outbound/add", handler.AddOutboundHandler)

	if config.pprof {
		router.Handler(http.MethodGet, "/debug/pprof/*item", http.DefaultServeMux)
	}

	router.GET("/", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, "%s\n", "Hello World!")
	})

	return router
}

func DefaultHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.Record(&log.AccessMessage{
		From:   "Web",
		To:     "DefaultHandler",
		Status: log.AccessAccepted,
		Detour: "Web",
	})
	fmt.Fprintf(w, "%s\n", "RESTful API version 1")
}

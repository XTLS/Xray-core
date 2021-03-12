package web

import (
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/xtls/xray-core/app/web/client"
	"github.com/xtls/xray-core/app/web/handler"
	"github.com/xtls/xray-core/core"
)

func Default(config *WebHandler) *httprouter.Router {
	router := httprouter.New()

	router.GET("/api/v1/statssys", handler.GetSysStatsHandler)

	if config.api.port != 0 {
		client.Client = client.NewServiceClient(config.api.address, config.api.port)
		router.GET("/api/v1/statsquery", handler.QueryStatsHandler)
		router.GET("/api/v1/statsquery/:pattern", handler.QueryStatsHandler)
		router.GET("/api/v1/stats", handler.GetStatsHandler)
		router.GET("/api/v1/stats/:name", handler.GetStatsHandler)
		router.DELETE("/api/v1/inbounds/:tag", handler.RemoveInboundHandler)
		router.POST("/api/v1/inbounds", handler.AddInboundHandler)
		router.DELETE("/api/v1/outbounds/:tag", handler.RemoveOutboundHandler)
		router.POST("/api/v1/outbounds", handler.AddOutboundHandler)
	}

	if config.pprof {
		router.Handler(http.MethodGet, "/debug/pprof/*item", http.DefaultServeMux)
	}

	if config.static != nil {
		for _, s := range config.static {
			if s.uri == "/" {
				router.NotFound = http.FileServer(http.Dir(s.filePath))
			} else {
				router.ServeFiles(s.uri+"/*filepath", http.Dir(s.filePath))
			}
		}
	} else {
		router.GET("/", DefaultHandler)
	}

	return router
}

func DefaultHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	for _, s := range core.VersionStatement() {
		fmt.Fprintf(w, "%s\n", s)
	}
}

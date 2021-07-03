package handler

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/xtls/xray-core/app/web/client"
	"github.com/xtls/xray-core/common/log"
)

//"Content-Type: application/json"
func AddInboundHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	res, err, _ := Convert(r)
	if err != nil {
		newError(err)
		return
	}
	client.Client.AddInbound(res)
}

func RemoveInboundHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	data := ps.ByName("tag")
	log.Record(&log.AccessMessage{
		From:   "Web",
		To:     "RemoveInboundHandler",
		Status: log.AccessAccepted,
		Detour: data,
	})
	client.Client.RemoveInbound(data)
}

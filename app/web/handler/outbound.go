package handler

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/xtls/xray-core/app/web/client"
	"github.com/xtls/xray-core/common/log"
)

func AddOutboundHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	res, err, _ := Convert(r)
	if err != nil {
		newError(err)
		return
	}
	client.Client.AddOutbound(res)
}

func RemoveOutboundHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	data := ps.ByName("tag")
	log.Record(&log.AccessMessage{
		From:   "Web",
		To:     "RemoveOutboundHandler",
		Status: log.AccessAccepted,
		Detour: data,
	})
	client.Client.RemoveOutbound(data)
}

package handler

import (
	"encoding/json"
	"log"
	"net/http"
)

func Convert(r *http.Request) ([]byte, error, map[string]interface{}) {
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		return nil, err, nil
	}
	decoder := json.NewDecoder(r.Body)
	var params map[string]interface{}
	if err := decoder.Decode(&params); err != nil {
		log.Println(err)
		return nil, err, nil
	}
	res, err := json.Marshal(params)
	if err != nil {
		log.Println(err)
		return nil, err, nil
	}
	return res, nil, params
}

package debug

import (
	"net/http"
)

func init() {
	go func() {
		http.ListenAndServe(":6060", nil)
	}()
}

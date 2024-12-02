package debug

import (
	"log"
	"net/http"
)

// StartDebugServer initializes and starts the HTTP server for debugging purposes.
func StartDebugServer() {
	// Start the server in a separate goroutine to avoid blocking
	go func() {
		if err := http.ListenAndServe(":6060", nil); err != nil {
			log.Fatalf("Failed to start debug server: %v", err)
		}
	}()
}

// init function calls StartDebugServer to set up the server when the package is initialized.
func init() {
	StartDebugServer()
}

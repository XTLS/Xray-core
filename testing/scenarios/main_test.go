package scenarios

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("XRAY_RUN_SCENARIOS") == "" {
		os.Exit(0)
	}
	genTestBinaryPath()
	defer testBinaryCleanFn()

	os.Exit(m.Run())
}

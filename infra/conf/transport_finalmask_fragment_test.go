package conf_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
)

func TestFinalMaskFragmentMode(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		want       fragment.Config_Mode
	}{
		{"default", `""`, fragment.Config_NORMAL},
		{"normal", `"normal"`, fragment.Config_NORMAL},
		{"normal_upper", `"NORMAL"`, fragment.Config_NORMAL},
		{"disorder", `"disorder"`, fragment.Config_DISORDER},
		{"disorder_upper", `"DISORDER"`, fragment.Config_DISORDER},
		{"disoob", `"disoob"`, fragment.Config_DISOOB},
		{"disoob_upper", `"DISOOB"`, fragment.Config_DISOOB},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := fmt.Sprintf(`{"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"1-3","delay":"10-20","mode":%s}}]}}`, test.mode)
			var config StreamConfig
			if err := json.Unmarshal([]byte(input), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			if len(built.Tcpmasks) != 1 {
				t.Fatalf("expected one mask, got %d", len(built.Tcpmasks))
			}
			instance, err := built.Tcpmasks[0].GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			got := instance.(*fragment.Config).Mode
			if got != test.want {
				t.Fatalf("expected mode %v, got %v", test.want, got)
			}
			// The runtime must initialize the finalmask machinery for every
			// mode without error.
			if _, err := internet.ToMemoryStreamConfig(built); err != nil {
				t.Fatalf("failed to initialize runtime finalmask: %v", err)
			}
		})
	}
	for _, mode := range []string{"wrong", "0", "oob", "dis order"} {
		input := fmt.Sprintf(`{"packets":"tlshello","mode":"%s"}`, mode)
		var config FragmentMask
		if err := json.Unmarshal([]byte(input), &config); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("expected invalid mode error for %q, got %v", mode, err)
		}
	}
}

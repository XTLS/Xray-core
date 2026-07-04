package core

import (
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestNewAppliesUseConeEnv(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		wantCone bool
	}{
		{
			name:     "enabled by default when env is false",
			envValue: "false",
			wantCone: true,
		},
		{
			name:     "disabled when env is true",
			envValue: "true",
			wantCone: false,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(platform.UseCone, test.envValue)

			server, err := New(&Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			got, ok := server.ctx.Value("cone").(bool)
			if !ok {
				t.Fatal("cone context value is missing or not a bool")
			}
			if got != test.wantCone {
				t.Fatalf("cone context value = %v, want %v", got, test.wantCone)
			}
		})
	}
}

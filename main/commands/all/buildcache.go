package all

import (
	"os"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBuildCache = &base.Command{
	UsageLine: `{{.Exec}} buildCache [-c config.json] [-o domain.cache]`,
	Short:     `Build domain matcher cache`,
	Long: `
Build domain matcher cache from a configuration file.

Example: {{.Exec}} buildCache -c config.json -o domain.cache
`,
}

func init() {
	cmdBuildCache.Run = executeBuildCache
}

var (
	configPath = cmdBuildCache.Flag.String("c", "config.json", "Config file path")
	outputPath = cmdBuildCache.Flag.String("o", "domain.cache", "Output cache file path")
)

func executeBuildCache(cmd *base.Command, args []string) {
	cf, err := os.Open(*configPath)
	if err != nil {
		base.Fatalf("failed to open config file: %v", err)
	}
	defer cf.Close()

	// prevent using existing cache
	domainMatcherPath := platform.NewEnvFlag(platform.MphCachePath).GetValue(func() string { return "" })
	if domainMatcherPath != "" {
		os.Setenv("XRAY_MPH_PATH", "")
		defer os.Setenv("XRAY_MPH_PATH", domainMatcherPath)
	}

	config, err := serial.DecodeJSONConfig(cf)
	if err != nil {
		base.Fatalf("failed to decode config file: %v", err)
	}

	if err := config.BuildMPHCache(outputPath); err != nil {
		base.Fatalf("failed to build MPH cache: %v", err)
	}
}

package all

import (
	"os"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBuildMphCache = &base.Command{
	UsageLine: `{{.Exec}} buildMphCache [-c config.json] [-o domain.cache]`,
	Short:     `Build domain matcher cache`,
	Long: `
Build domain matcher cache from a configuration file.

Example: {{.Exec}} buildMphCache -c config.json -o domain.cache
`,
}

func init() {
	cmdBuildMphCache.Run = executeBuildMphCache
}

var (
	configPath = cmdBuildMphCache.Flag.String("c", "config.json", "Config file path")
	outputPath = cmdBuildMphCache.Flag.String("o", "domain.cache", "Output cache file path")
)

func executeBuildMphCache(cmd *base.Command, args []string) {
	cf, err := os.Open(*configPath)
	if err != nil {
		base.Fatalf("failed to open config file: %v", err)
	}
	defer cf.Close()

	// prevent using existing cache
	domainMatcherPath := platform.NewEnvFlag(platform.MphCachePath).GetValue(func() string { return "" })
	if domainMatcherPath != "" {
		os.Setenv("XRAY_MPH_CACHE", "")
		defer os.Setenv("XRAY_MPH_CACHE", domainMatcherPath)
	}

	config, err := serial.DecodeJSONConfig(cf)
	if err != nil {
		base.Fatalf("failed to decode config file: %v", err)
	}

	if err := config.BuildMPHCache(outputPath); err != nil {
		base.Fatalf("failed to build MPH cache: %v", err)
	}
}

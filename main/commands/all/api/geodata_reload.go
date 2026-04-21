package api

import (
	geodataService "github.com/xtls/xray-core/app/geodata/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdReloadGeoIP = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api reloadgeoip [--server=127.0.0.1:8080]",
	Short:       "Reload GeoIP data",
	Long: `
Reload GeoIP data in Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeReloadGeoIP,
}

var cmdReloadGeoSite = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api reloadgeosite [--server=127.0.0.1:8080]",
	Short:       "Reload GeoSite data",
	Long: `
Reload GeoSite data in Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeReloadGeoSite,
}

func executeReloadGeoIP(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := geodataService.NewGeodataServiceClient(conn)
	r := &geodataService.ReloadGeoIPRequest{}
	resp, err := client.ReloadGeoIP(ctx, r)
	if err != nil {
		base.Fatalf("failed to reload GeoIP: %s", err)
	}
	showJSONResponse(resp)
}

func executeReloadGeoSite(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := geodataService.NewGeodataServiceClient(conn)
	r := &geodataService.ReloadGeoSiteRequest{}
	resp, err := client.ReloadGeoSite(ctx, r)
	if err != nil {
		base.Fatalf("failed to reload GeoSite: %s", err)
	}
	showJSONResponse(resp)
}

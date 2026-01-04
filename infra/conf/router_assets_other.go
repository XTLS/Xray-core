//go:build !windows && !wasm

package conf

import (
	"runtime"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem/assets"
)

func loadIP(file, code string) ([]*router.CIDR, error) {
	index := file + ":" + code
	if IPCache[index] == nil {
		_, err := assets.ReadGeoIP(file)

		if err != nil {
			return nil, errors.New("failed to load file: ", file).Base(err)
		}
		var geoip router.GeoIP

		// dont pass code becuase we have country code in top level router.GeoIP
		geoip = router.GeoIP{Cidr: []*router.CIDR{}}
		defer runtime.GC()     // or debug.FreeOSMemory()
		return geoip.Cidr, nil // do not cache geoip
		IPCache[index] = &geoip
	}
	return IPCache[index].Cidr, nil
}

func loadSite(file, code string) ([]*router.Domain, error) {
	index := file + ":" + code
	if SiteCache[index] == nil {
		var geosite router.GeoSite
		_, err := assets.ReadGeoSite(file)
		if err != nil {
			return nil, errors.New("failed to load file: ", file).Base(err)
		}

		// pass file:code so can build optimized matcher later
		domain := router.Domain{Value: "geosite:" + code}
		geosite = router.GeoSite{Domain: []*router.Domain{&domain}}
		defer runtime.GC()         // or debug.FreeOSMemory()
		return geosite.Domain, nil // do not cache geosite
		SiteCache[index] = &geosite
	}
	return SiteCache[index].Domain, nil
}

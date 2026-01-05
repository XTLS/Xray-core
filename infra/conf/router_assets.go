//go:build !ios && !darwin

package conf

import (
	"runtime"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/platform/filesystem/assets"
	"google.golang.org/protobuf/proto"
)

func loadFile(file string) ([]byte, error) {
	if FileCache[file] == nil {
		bs, err := filesystem.ReadAsset(file)
		if err != nil {
			return nil, errors.New("failed to open file: ", file).Base(err)
		}
		if len(bs) == 0 {
			return nil, errors.New("empty file: ", file)
		}
		// Do not cache file, may save RAM when there
		// are many files, but consume CPU each time.
		return bs, nil
		FileCache[file] = bs
	}
	return FileCache[file], nil
}

func loadIP(file, code string) ([]*router.CIDR, error) {
	index := file + ":" + code
	if IPCache[index] == nil {
		bs, err := loadFile(file)
		if err != nil {
			return nil, errors.New("failed to load file: ", file).Base(err)
		}
		bs, _ = assets.Find(bs, []byte(code))
		if bs == nil {
			return nil, errors.New("code not found in ", file, ": ", code)
		}
		var geoip router.GeoIP
		if err := proto.Unmarshal(bs, &geoip); err != nil {
			return nil, errors.New("error unmarshal IP in ", file, ": ", code).Base(err)
		}
		defer runtime.GC()     // or debug.FreeOSMemory()
		return geoip.Cidr, nil // do not cache geoip
		IPCache[index] = &geoip
	}
	return IPCache[index].Cidr, nil
}

func loadSite(file, code string) ([]*router.Domain, error) {
	index := file + ":" + code
	if SiteCache[index] == nil {
		bs, err := loadFile(file)
		if err != nil {
			return nil, errors.New("failed to load file: ", file).Base(err)
		}
		bs, _ = assets.Find(bs, []byte(code))
		if bs == nil {
			return nil, errors.New("list not found in ", file, ": ", code)
		}
		var geosite router.GeoSite
		if err := proto.Unmarshal(bs, &geosite); err != nil {
			return nil, errors.New("error unmarshal Site in ", file, ": ", code).Base(err)
		}
		defer runtime.GC()         // or debug.FreeOSMemory()
		return geosite.Domain, nil // do not cache geosite
		SiteCache[index] = &geosite
	}
	return SiteCache[index].Domain, nil
}

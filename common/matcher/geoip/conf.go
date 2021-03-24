package geoip

import (
	"runtime"

	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/platform/filesystem"
)

var (
	FileCache = make(map[string][]byte)
	IPCache   = make(map[string]*GeoIP)
)

func LoadGeoIP(code string) ([]*CIDR, error) {
	return LoadIPFile("geoip.dat", code)
}

func LoadIPFile(file, code string) ([]*CIDR, error) {
	index := file + ":" + code
	if IPCache[index] == nil {
		bs, err := loadFile(file)
		if err != nil {
			return nil, newError("failed to load file: ", file).Base(err)
		}
		bs = find(bs, []byte(code))
		if bs == nil {
			return nil, newError("code not found in ", file, ": ", code)
		}
		var geoipdat GeoIP
		if err := proto.Unmarshal(bs, &geoipdat); err != nil {
			return nil, newError("error unmarshal IP in ", file, ": ", code).Base(err)
		}
		defer runtime.GC()        // or debug.FreeOSMemory()
		return geoipdat.Cidr, nil // do not cache geoip
		IPCache[index] = &geoipdat
	}
	return IPCache[index].Cidr, nil
}

func loadFile(file string) ([]byte, error) {
	if FileCache[file] == nil {
		bs, err := filesystem.ReadAsset(file)
		if err != nil {
			return nil, newError("failed to open file: ", file).Base(err)
		}
		if len(bs) == 0 {
			return nil, newError("empty file: ", file)
		}
		// Do not cache file, may save RAM when there
		// are many files, but consume CPU each time.
		return bs, nil
		FileCache[file] = bs
	}
	return FileCache[file], nil
}

func find(data, code []byte) []byte {
	codeL := len(code)
	if codeL == 0 {
		return nil
	}
	for {
		dataL := len(data)
		if dataL < 2 {
			return nil
		}
		x, y := proto.DecodeVarint(data[1:])
		if x == 0 && y == 0 {
			return nil
		}
		headL, bodyL := 1+y, int(x)
		dataL -= headL
		if dataL < bodyL {
			return nil
		}
		data = data[headL:]
		if int(data[1]) == codeL {
			for i := 0; i < codeL && data[2+i] == code[i]; i++ {
				if i+1 == codeL {
					return data[:bodyL]
				}
			}
		}
		if dataL == bodyL {
			return nil
		}
		data = data[bodyL:]
	}
}

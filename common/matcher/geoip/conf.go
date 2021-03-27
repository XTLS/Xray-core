package geoip

import (
	"runtime"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/net"
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

func ParaseIPList(ips []string) ([]*GeoIP, error) {
	var geoipList []*GeoIP
	var customCidrs []*CIDR

	for _, ip := range ips {
		if strings.HasPrefix(ip, "geoip:") {
			country := ip[6:]
			geoipc, err := LoadGeoIP(strings.ToUpper(country))
			if err != nil {
				return nil, newError("failed to load GeoIP: ", country).Base(err)
			}

			geoipList = append(geoipList, &GeoIP{
				CountryCode: strings.ToUpper(country),
				Cidr:        geoipc,
			})
			continue
		}
		var isExtDatFile = 0
		{
			const prefix = "ext:"
			if strings.HasPrefix(ip, prefix) {
				isExtDatFile = len(prefix)
			}
			const prefixQualified = "ext-ip:"
			if strings.HasPrefix(ip, prefixQualified) {
				isExtDatFile = len(prefixQualified)
			}
		}
		if isExtDatFile != 0 {
			kv := strings.Split(ip[isExtDatFile:], ":")
			if len(kv) != 2 {
				return nil, newError("invalid external resource: ", ip)
			}

			filename := kv[0]
			country := kv[1]
			geoipc, err := LoadIPFile(filename, strings.ToUpper(country))
			if err != nil {
				return nil, newError("failed to load IPs: ", country, " from ", filename).Base(err)
			}

			geoipList = append(geoipList, &GeoIP{
				CountryCode: strings.ToUpper(filename + "_" + country),
				Cidr:        geoipc,
			})

			continue
		}

		ipRule, err := ParseIP(ip)
		if err != nil {
			return nil, newError("invalid IP: ", ip).Base(err)
		}
		customCidrs = append(customCidrs, ipRule)
	}

	if len(customCidrs) > 0 {
		geoipList = append(geoipList, &GeoIP{
			Cidr: customCidrs,
		})
	}

	return geoipList, nil
}

func ParseIP(s string) (*CIDR, error) {
	var addr, mask string
	i := strings.Index(s, "/")
	if i < 0 {
		addr = s
	} else {
		addr = s[:i]
		mask = s[i+1:]
	}
	ip := net.ParseAddress(addr)
	switch ip.Family() {
	case net.AddressFamilyIPv4:
		bits := uint32(32)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, newError("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 32 {
			return nil, newError("invalid network mask for router: ", bits)
		}
		return &CIDR{
			Ip:     ip.IP(),
			Prefix: bits,
		}, nil
	case net.AddressFamilyIPv6:
		bits := uint32(128)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, newError("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 128 {
			return nil, newError("invalid network mask for router: ", bits)
		}
		return &CIDR{
			Ip:     ip.IP(),
			Prefix: bits,
		}, nil
	default:
		return nil, newError("unsupported address for router: ", s)
	}
}

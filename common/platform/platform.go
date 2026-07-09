package platform // import "github.com/xtls/xray-core/common/platform"

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ConfigLocation  = "xray.location.config"
	ConfdirLocation = "xray.location.confdir"
	AssetLocation   = "xray.location.asset"
	CertLocation    = "xray.location.cert"

	UseReadV         = "xray.buf.readv"
	UseFreedomSplice = "xray.buf.splice"
	UseVmessPadding  = "xray.vmess.padding"
	UseCone          = "xray.cone.disabled"
	UseStrictJSON    = "xray.json.strict"

	BufferSize           = "xray.ray.buffer.size"
	BrowserDialerAddress = "xray.browser.dialer"
	XUDPLog              = "xray.xudp.show"
	XUDPBaseKey          = "xray.xudp.basekey"

	TunFdKey = "xray.tun.fd"
)

var configEnvKeys = map[string]string{
	NormalizeEnvName(AssetLocation):        AssetLocation,
	NormalizeEnvName(CertLocation):         CertLocation,
	NormalizeEnvName(UseReadV):             UseReadV,
	NormalizeEnvName(UseFreedomSplice):     UseFreedomSplice,
	NormalizeEnvName(UseVmessPadding):      UseVmessPadding,
	NormalizeEnvName(UseCone):              UseCone,
	NormalizeEnvName(BufferSize):           BufferSize,
	NormalizeEnvName(BrowserDialerAddress): BrowserDialerAddress,
	NormalizeEnvName(XUDPLog):              XUDPLog,
	NormalizeEnvName(XUDPBaseKey):          XUDPBaseKey,
	NormalizeEnvName(TunFdKey):             TunFdKey,
}

type EnvFlag struct {
	Name    string
	AltName string
}

func NewEnvFlag(name string) EnvFlag {
	return EnvFlag{
		Name:    name,
		AltName: NormalizeEnvName(name),
	}
}

func (f EnvFlag) GetValue(defaultValue func() string) string {
	if v, found := os.LookupEnv(f.Name); found {
		return v
	}
	if len(f.AltName) > 0 {
		if v, found := os.LookupEnv(f.AltName); found {
			return v
		}
	}

	return defaultValue()
}

func (f EnvFlag) GetValueAsInt(defaultValue int) int {
	useDefaultValue := false
	s := f.GetValue(func() string {
		useDefaultValue = true
		return ""
	})
	if useDefaultValue {
		return defaultValue
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return defaultValue
	}
	return int(v)
}

func NormalizeEnvName(name string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(name)), ".", "_")
}

// CanonicalConfigEnvKey returns the canonical dotted key for an environment
// setting that may be declared inside an already parsed Xray config. Pre-load
// keys such as xray.json.strict, xray.location.config and xray.location.confdir
// are intentionally excluded.
func CanonicalConfigEnvKey(key string) (string, bool) {
	canonicalKey, ok := configEnvKeys[NormalizeEnvName(key)]
	return canonicalKey, ok
}

func getExecutableDir() string {
	exec, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exec)
}

func GetConfigurationPath() string {
	configPath := NewEnvFlag(ConfigLocation).GetValue(getExecutableDir)
	return filepath.Join(configPath, "config.json")
}

// GetConfDirPath reads "xray.location.confdir"
func GetConfDirPath() string {
	configPath := NewEnvFlag(ConfdirLocation).GetValue(func() string { return "" })
	return configPath
}

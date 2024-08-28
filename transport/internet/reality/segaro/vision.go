package segaro

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	goReality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/reality"
)

type SegaroConfig struct {
	RealityConfig   *reality.Config
	GoRealityConfig *goReality.Config
}

func (sc *SegaroConfig) GetPaddingSize() uint32 {
	if sc.RealityConfig != nil {
		return sc.RealityConfig.PaddingSize
	}
	return sc.GoRealityConfig.PaddingSize
}

func (sc *SegaroConfig) GetSubChunkSize() uint32 {
	if sc.RealityConfig != nil {
		return sc.RealityConfig.SubchunkSize
	}
	return sc.GoRealityConfig.SubChunkSize
}

func (sc *SegaroConfig) GetRandSize() (int, int) {
	var randomPacket string
	if sc.RealityConfig != nil {
		randomPacket = sc.RealityConfig.RandPacket
	} else {
		randomPacket = sc.GoRealityConfig.RandPacket
	}
	randPacket := strings.Split(randomPacket, "-")
	if len(randPacket) == 0{
		return 0, 0
	}
	min, _ := strconv.Atoi(randPacket[0])
	if len(randPacket) == 1 {
		return min, min
	}
	max, _ := strconv.Atoi(randPacket[1])
	return min, max
}

func (sc *SegaroConfig) GetSplitSize() (int, int) {
	var splitPacket string
	if sc.RealityConfig != nil {
		splitPacket = sc.RealityConfig.SplitPacket
	} else {
		splitPacket = sc.GoRealityConfig.SplitPacket
	}
	splitedPacket := strings.Split(splitPacket, "-")
	if len(splitedPacket) == 0{
		return 0, 0
	}
	min, _ := strconv.Atoi(splitedPacket[0])
	if len(splitedPacket) == 1 {
		return min, min
	}
	max, _ := strconv.Atoi(splitedPacket[1])
	return min, max
}

// GetPrivateField, returns the private fieldName from v object
func GetPrivateField(v interface{}, fieldName string) (interface{}, error) {
	rv := reflect.ValueOf(v)

	// If the value is not addressable, make a copy that is addressable
	if !rv.CanAddr() {
		rs := reflect.New(rv.Type()).Elem()
		rs.Set(rv)
		rv = rs
	}

	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, errors.New(fmt.Sprintf("expected struct, got %v", rv.Kind()))
	}

	rt := rv.Type()
	structField, ok := rt.FieldByName(fieldName)
	if !ok {
		return nil, errors.New(fmt.Sprintf("field %s not found", fieldName))
	}
	fieldPtr := unsafe.Pointer(rv.UnsafeAddr() + structField.Offset)
	fieldValue := reflect.NewAt(structField.Type, fieldPtr).Elem()
	return fieldValue.Interface(), nil
}

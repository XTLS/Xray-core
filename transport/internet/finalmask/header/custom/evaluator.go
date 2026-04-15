package custom

import (
	"encoding/binary"
	"net"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type evalValue struct {
	bytes   []byte
	u64     *uint64
	isBytes bool
}

type evalContext struct {
	vars     map[string][]byte
	metadata map[string]evalValue
}

func newEvalContext() *evalContext {
	return &evalContext{
		vars:     make(map[string][]byte),
		metadata: make(map[string]evalValue),
	}
}

func newEvalContextWithAddrs(local, remote net.Addr) *evalContext {
	ctx := newEvalContext()
	loadMetadata(ctx.metadata, "local", local)
	loadMetadata(ctx.metadata, "remote", remote)
	return ctx
}

func evaluateUDPItems(items []*UDPItem) ([]byte, error) {
	return evaluateUDPItemsWithContext(items, newEvalContext())
}

func evaluateUDPItemsWithContext(items []*UDPItem, ctx *evalContext) ([]byte, error) {
	var out []byte
	for _, item := range items {
		value, err := evaluateItem(item.Rand, item.RandMin, item.RandMax, item.Packet, item.Save, item.Var, item.Expr, ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, value...)
	}
	return out, nil
}

func measureUDPItems(items []*UDPItem) (int, error) {
	return measureUDPItemsWithFallback(items, nil)
}

func measureUDPItemsWithFallback(items []*UDPItem, fallback map[string]int) (int, error) {
	sizeCtx := make(map[string]int)
	for key, value := range fallback {
		sizeCtx[key] = value
	}
	total := 0
	for _, item := range items {
		itemSize, err := measureItem(item.Rand, item.Packet, item.Save, item.Var, item.Expr, sizeCtx)
		if err != nil {
			return 0, err
		}
		total += itemSize
	}
	return total, nil
}

func collectSavedUDPSizes(items []*UDPItem) map[string]int {
	sizeCtx := make(map[string]int)
	for _, item := range items {
		itemSize, err := measureItem(item.Rand, item.Packet, item.Save, item.Var, item.Expr, sizeCtx)
		if err != nil {
			continue
		}
		if item.Save != "" {
			sizeCtx[item.Save] = itemSize
		}
	}
	return sizeCtx
}

func measureItem(randLen int32, packet []byte, save, varName string, expr *Expr, sizeCtx map[string]int) (int, error) {
	var size int
	switch {
	case randLen > 0:
		size = int(randLen)
	case len(packet) > 0:
		size = len(packet)
	case varName != "":
		length, ok := sizeCtx[varName]
		if !ok {
			return 0, errors.New("unknown variable: ", varName)
		}
		size = length
	case expr != nil:
		exprSize, err := measureExpr(expr, sizeCtx)
		if err != nil {
			return 0, err
		}
		size = exprSize
	default:
		size = 0
	}

	if save != "" {
		sizeCtx[save] = size
	}

	return size, nil
}

func evaluateTCPSequence(sequence *TCPSequence) ([]byte, error) {
	ctx := newEvalContext()
	var out []byte
	for _, item := range sequence.Sequence {
		value, err := evaluateItem(item.Rand, item.RandMin, item.RandMax, item.Packet, item.Save, item.Var, item.Expr, ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, value...)
	}
	return out, nil
}

func evaluateItem(randLen, randMin, randMax int32, packet []byte, save, varName string, expr *Expr, ctx *evalContext) ([]byte, error) {
	var value []byte
	switch {
	case randLen > 0:
		value = make([]byte, randLen)
		crypto.RandBytesBetween(value, byte(randMin), byte(randMax))
	case len(packet) > 0:
		value = append([]byte(nil), packet...)
	case varName != "":
		saved, ok := ctx.vars[varName]
		if !ok {
			return nil, errors.New("unknown variable: ", varName)
		}
		value = append([]byte(nil), saved...)
	case expr != nil:
		evaluated, err := evaluateExpr(expr, ctx)
		if err != nil {
			return nil, err
		}
		bytesValue, err := evaluated.asBytes()
		if err != nil {
			return nil, err
		}
		value = bytesValue
	default:
		value = nil
	}

	if save != "" {
		ctx.vars[save] = append([]byte(nil), value...)
	}

	return value, nil
}

func evaluateExpr(expr *Expr, ctx *evalContext) (evalValue, error) {
	switch expr.GetOp() {
	case "concat":
		var out []byte
		for _, arg := range expr.GetArgs() {
			value, err := evaluateExprArg(arg, ctx)
			if err != nil {
				return evalValue{}, err
			}
			bytesValue, err := value.asBytes()
			if err != nil {
				return evalValue{}, err
			}
			out = append(out, bytesValue...)
		}
		return evalValue{bytes: out, isBytes: true}, nil
	case "slice":
		if len(expr.GetArgs()) != 3 {
			return evalValue{}, errors.New("slice expects 3 args")
		}
		source, err := evaluateExprArg(expr.GetArgs()[0], ctx)
		if err != nil {
			return evalValue{}, err
		}
		offset, err := evaluateExprArg(expr.GetArgs()[1], ctx)
		if err != nil {
			return evalValue{}, err
		}
		length, err := evaluateExprArg(expr.GetArgs()[2], ctx)
		if err != nil {
			return evalValue{}, err
		}
		sourceBytes, err := source.asBytes()
		if err != nil {
			return evalValue{}, err
		}
		offsetU64, err := offset.asU64()
		if err != nil {
			return evalValue{}, err
		}
		lengthU64, err := length.asU64()
		if err != nil {
			return evalValue{}, err
		}
		end := offsetU64 + lengthU64
		if end > uint64(len(sourceBytes)) {
			return evalValue{}, errors.New("slice out of bounds")
		}
		return evalValue{bytes: append([]byte(nil), sourceBytes[offsetU64:end]...), isBytes: true}, nil
	case "xor16":
		return evaluateXor(expr.GetArgs(), 0xFFFF, 2, ctx)
	case "xor32":
		return evaluateXor(expr.GetArgs(), 0xFFFFFFFF, 4, ctx)
	case "be16":
		return evaluatePack(expr.GetArgs(), "be16", 2, binary.BigEndian, ctx)
	case "be32":
		return evaluatePack(expr.GetArgs(), "be32", 4, binary.BigEndian, ctx)
	case "le16":
		return evaluatePack(expr.GetArgs(), "le16", 2, binary.LittleEndian, ctx)
	case "le32":
		return evaluatePack(expr.GetArgs(), "le32", 4, binary.LittleEndian, ctx)
	case "le64":
		return evaluatePack(expr.GetArgs(), "le64", 8, binary.LittleEndian, ctx)
	case "pad":
		return evaluatePad(expr.GetArgs(), ctx)
	case "truncate":
		return evaluateTruncate(expr.GetArgs(), ctx)
	case "add":
		return evaluateBinaryU64Op(expr.GetArgs(), "add", ctx, func(left, right uint64) (uint64, error) {
			if left > ^uint64(0)-right {
				return 0, errors.New("add overflow")
			}
			return left + right, nil
		})
	case "sub":
		return evaluateBinaryU64Op(expr.GetArgs(), "sub", ctx, func(left, right uint64) (uint64, error) {
			if left < right {
				return 0, errors.New("sub underflow")
			}
			return left - right, nil
		})
	case "and":
		return evaluateBinaryU64Op(expr.GetArgs(), "and", ctx, func(left, right uint64) (uint64, error) {
			return left & right, nil
		})
	case "or":
		return evaluateBinaryU64Op(expr.GetArgs(), "or", ctx, func(left, right uint64) (uint64, error) {
			return left | right, nil
		})
	case "shl":
		return evaluateShift(expr.GetArgs(), "shl", ctx, func(value uint64, shift uint) (uint64, error) {
			if shift >= 64 {
				return 0, errors.New("shift out of range")
			}
			if value > (^uint64(0) >> shift) {
				return 0, errors.New("shl overflow")
			}
			return value << shift, nil
		})
	case "shr":
		return evaluateShift(expr.GetArgs(), "shr", ctx, func(value uint64, shift uint) (uint64, error) {
			if shift >= 64 {
				return 0, errors.New("shift out of range")
			}
			return value >> shift, nil
		})
	default:
		return evalValue{}, errors.New("unsupported expr op: ", expr.GetOp())
	}
}

func evaluatePack(args []*ExprArg, name string, width int, order binary.ByteOrder, ctx *evalContext) (evalValue, error) {
	if len(args) != 1 {
		return evalValue{}, errors.New(name, " expects 1 arg")
	}
	value, err := evaluateExprArg(args[0], ctx)
	if err != nil {
		return evalValue{}, err
	}
	u64Value, err := value.asU64()
	if err != nil {
		return evalValue{}, err
	}

	switch width {
	case 2:
		if u64Value > 0xFFFF {
			return evalValue{}, errors.New(name, " overflow")
		}
		out := make([]byte, 2)
		order.PutUint16(out, uint16(u64Value))
		return evalValue{bytes: out, isBytes: true}, nil
	case 4:
		if u64Value > 0xFFFFFFFF {
			return evalValue{}, errors.New(name, " overflow")
		}
		out := make([]byte, 4)
		order.PutUint32(out, uint32(u64Value))
		return evalValue{bytes: out, isBytes: true}, nil
	case 8:
		out := make([]byte, 8)
		order.PutUint64(out, u64Value)
		return evalValue{bytes: out, isBytes: true}, nil
	default:
		return evalValue{}, errors.New("unsupported pack width")
	}
}

func evaluatePad(args []*ExprArg, ctx *evalContext) (evalValue, error) {
	if len(args) != 3 {
		return evalValue{}, errors.New("pad expects 3 args")
	}
	source, err := evaluateExprArg(args[0], ctx)
	if err != nil {
		return evalValue{}, err
	}
	target, err := evaluateExprArg(args[1], ctx)
	if err != nil {
		return evalValue{}, err
	}
	fill, err := evaluateExprArg(args[2], ctx)
	if err != nil {
		return evalValue{}, err
	}
	sourceBytes, err := source.asBytes()
	if err != nil {
		return evalValue{}, err
	}
	targetU64, err := target.asU64()
	if err != nil {
		return evalValue{}, err
	}
	fillBytes, err := fill.asBytes()
	if err != nil {
		return evalValue{}, err
	}
	if len(fillBytes) == 0 {
		return evalValue{}, errors.New("pad fill must not be empty")
	}
	if targetU64 < uint64(len(sourceBytes)) {
		return evalValue{}, errors.New("pad target shorter than source")
	}

	out := append([]byte(nil), sourceBytes...)
	for uint64(len(out)) < targetU64 {
		remaining := int(targetU64) - len(out)
		if remaining >= len(fillBytes) {
			out = append(out, fillBytes...)
			continue
		}
		out = append(out, fillBytes[:remaining]...)
	}
	return evalValue{bytes: out, isBytes: true}, nil
}

func evaluateTruncate(args []*ExprArg, ctx *evalContext) (evalValue, error) {
	if len(args) != 2 {
		return evalValue{}, errors.New("truncate expects 2 args")
	}
	source, err := evaluateExprArg(args[0], ctx)
	if err != nil {
		return evalValue{}, err
	}
	length, err := evaluateExprArg(args[1], ctx)
	if err != nil {
		return evalValue{}, err
	}
	sourceBytes, err := source.asBytes()
	if err != nil {
		return evalValue{}, err
	}
	lengthU64, err := length.asU64()
	if err != nil {
		return evalValue{}, err
	}
	if lengthU64 > uint64(len(sourceBytes)) {
		return evalValue{}, errors.New("truncate out of bounds")
	}
	return evalValue{bytes: append([]byte(nil), sourceBytes[:lengthU64]...), isBytes: true}, nil
}

func evaluateBinaryU64Op(args []*ExprArg, name string, ctx *evalContext, op func(left, right uint64) (uint64, error)) (evalValue, error) {
	if len(args) != 2 {
		return evalValue{}, errors.New(name, " expects 2 args")
	}
	left, err := evaluateExprArg(args[0], ctx)
	if err != nil {
		return evalValue{}, err
	}
	right, err := evaluateExprArg(args[1], ctx)
	if err != nil {
		return evalValue{}, err
	}
	leftU64, err := left.asU64()
	if err != nil {
		return evalValue{}, err
	}
	rightU64, err := right.asU64()
	if err != nil {
		return evalValue{}, err
	}
	result, err := op(leftU64, rightU64)
	if err != nil {
		return evalValue{}, err
	}
	return evalValue{u64: &result}, nil
}

func evaluateShift(args []*ExprArg, name string, ctx *evalContext, op func(value uint64, shift uint) (uint64, error)) (evalValue, error) {
	if len(args) != 2 {
		return evalValue{}, errors.New(name, " expects 2 args")
	}
	value, err := evaluateExprArg(args[0], ctx)
	if err != nil {
		return evalValue{}, err
	}
	shift, err := evaluateExprArg(args[1], ctx)
	if err != nil {
		return evalValue{}, err
	}
	valueU64, err := value.asU64()
	if err != nil {
		return evalValue{}, err
	}
	shiftU64, err := shift.asU64()
	if err != nil {
		return evalValue{}, err
	}
	if shiftU64 >= 64 {
		return evalValue{}, errors.New("shift out of range")
	}
	result, err := op(valueU64, uint(shiftU64))
	if err != nil {
		return evalValue{}, err
	}
	return evalValue{u64: &result}, nil
}

func evaluateXor(args []*ExprArg, mask uint64, width int, ctx *evalContext) (evalValue, error) {
	if len(args) != 2 {
		return evalValue{}, errors.New("xor expects 2 args")
	}
	left, err := evaluateExprArg(args[0], ctx)
	if err != nil {
		return evalValue{}, err
	}
	right, err := evaluateExprArg(args[1], ctx)
	if err != nil {
		return evalValue{}, err
	}
	leftU64, err := left.asU64()
	if err != nil {
		return evalValue{}, err
	}
	rightU64, err := right.asU64()
	if err != nil {
		return evalValue{}, err
	}
	if width == 2 && (leftU64 > 0xFFFF || rightU64 > 0xFFFF) {
		return evalValue{}, errors.New("xor16 overflow")
	}
	if width == 4 && (leftU64 > 0xFFFFFFFF || rightU64 > 0xFFFFFFFF) {
		return evalValue{}, errors.New("xor32 overflow")
	}
	result := (leftU64 ^ rightU64) & mask
	return evalValue{u64: &result}, nil
}

func measureExpr(expr *Expr, sizeCtx map[string]int) (int, error) {
	switch expr.GetOp() {
	case "concat":
		total := 0
		for _, arg := range expr.GetArgs() {
			size, err := measureExprArg(arg, sizeCtx)
			if err != nil {
				return 0, err
			}
			total += size
		}
		return total, nil
	case "slice":
		if len(expr.GetArgs()) != 3 {
			return 0, errors.New("slice expects 3 args")
		}
		lengthArg := expr.GetArgs()[2]
		if value, ok := lengthArg.GetValue().(*ExprArg_U64); ok {
			return int(value.U64), nil
		}
		return 0, errors.New("slice length must be u64")
	case "be16":
		return 2, nil
	case "be32":
		return 4, nil
	case "le16":
		return 2, nil
	case "le32":
		return 4, nil
	case "le64":
		return 8, nil
	case "pad":
		if len(expr.GetArgs()) != 3 {
			return 0, errors.New("pad expects 3 args")
		}
		lengthArg := expr.GetArgs()[1]
		if value, ok := lengthArg.GetValue().(*ExprArg_U64); ok {
			return int(value.U64), nil
		}
		return 0, errors.New("pad length must be u64")
	case "truncate":
		if len(expr.GetArgs()) != 2 {
			return 0, errors.New("truncate expects 2 args")
		}
		lengthArg := expr.GetArgs()[1]
		if value, ok := lengthArg.GetValue().(*ExprArg_U64); ok {
			return int(value.U64), nil
		}
		return 0, errors.New("truncate length must be u64")
	default:
		return 0, errors.New("expr size is not bytes for op: ", expr.GetOp())
	}
}

func evaluateExprArg(arg *ExprArg, ctx *evalContext) (evalValue, error) {
	switch value := arg.GetValue().(type) {
	case *ExprArg_Bytes:
		return evalValue{bytes: append([]byte(nil), value.Bytes...), isBytes: true}, nil
	case *ExprArg_U64:
		return evalValue{u64: &value.U64}, nil
	case *ExprArg_Var:
		saved, ok := ctx.vars[value.Var]
		if !ok {
			return evalValue{}, errors.New("unknown variable: ", value.Var)
		}
		return evalValue{bytes: append([]byte(nil), saved...), isBytes: true}, nil
	case *ExprArg_Metadata:
		metadata, ok := ctx.metadata[value.Metadata]
		if !ok {
			return evalValue{}, errors.New("unknown metadata: ", value.Metadata)
		}
		return metadata, nil
	case *ExprArg_Expr:
		return evaluateExpr(value.Expr, ctx)
	default:
		return evalValue{}, errors.New("empty expr arg")
	}
}

func measureExprArg(arg *ExprArg, sizeCtx map[string]int) (int, error) {
	switch value := arg.GetValue().(type) {
	case *ExprArg_Bytes:
		return len(value.Bytes), nil
	case *ExprArg_U64:
		return 0, errors.New("u64 arg has no byte width")
	case *ExprArg_Var:
		length, ok := sizeCtx[value.Var]
		if !ok {
			return 0, errors.New("unknown variable: ", value.Var)
		}
		return length, nil
	case *ExprArg_Metadata:
		return 0, errors.New("metadata not implemented: ", value.Metadata)
	case *ExprArg_Expr:
		return measureExpr(value.Expr, sizeCtx)
	default:
		return 0, errors.New("empty expr arg")
	}
}

func (v evalValue) asBytes() ([]byte, error) {
	if v.isBytes {
		return append([]byte(nil), v.bytes...), nil
	}
	return nil, errors.New("expr value is not bytes")
}

func (v evalValue) asU64() (uint64, error) {
	if v.u64 != nil {
		return *v.u64, nil
	}
	return 0, errors.New("expr value is not u64")
}

func sizeMapFromEvalContext(ctx *evalContext) map[string]int {
	sizes := make(map[string]int, len(ctx.vars))
	for key, value := range ctx.vars {
		sizes[key] = len(value)
	}
	return sizes
}

func loadMetadata(dst map[string]evalValue, prefix string, addr net.Addr) {
	if addr == nil {
		return
	}

	switch value := addr.(type) {
	case *net.UDPAddr:
		loadIPPortMetadata(dst, prefix, value.IP, value.Port)
	case *net.TCPAddr:
		loadIPPortMetadata(dst, prefix, value.IP, value.Port)
	}
}

func loadIPPortMetadata(dst map[string]evalValue, prefix string, ip net.IP, port int) {
	portValue := uint64(port)
	dst[prefix+"_port"] = evalValue{u64: &portValue}
	if prefix == "remote" {
		dst["src_port_u16"] = evalValue{u64: &portValue}
	} else if prefix == "local" {
		dst["dst_port_u16"] = evalValue{u64: &portValue}
	}

	if ip4 := ip.To4(); ip4 != nil {
		ipValue := uint64(binary.BigEndian.Uint32(ip4))
		dst[prefix+"_ip4_u32"] = evalValue{u64: &ipValue}
		if prefix == "remote" {
			dst["src_ip4_u32"] = evalValue{u64: &ipValue}
		} else if prefix == "local" {
			dst["dst_ip4_u32"] = evalValue{u64: &ipValue}
		}
	}
}

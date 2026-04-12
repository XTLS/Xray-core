package custom

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type evalValue struct {
	bytes []byte
	u64   *uint64
}

type evalContext struct {
	vars map[string][]byte
}

func newEvalContext() *evalContext {
	return &evalContext{
		vars: make(map[string][]byte),
	}
}

func evaluateUDPItems(items []*UDPItem) ([]byte, error) {
	ctx := newEvalContext()
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
		return evalValue{bytes: out}, nil
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
		return evalValue{bytes: append([]byte(nil), sourceBytes[offsetU64:end]...)}, nil
	case "xor16":
		return evaluateXor(expr.GetArgs(), 0xFFFF, 2, ctx)
	case "xor32":
		return evaluateXor(expr.GetArgs(), 0xFFFFFFFF, 4, ctx)
	case "be16":
		if len(expr.GetArgs()) != 1 {
			return evalValue{}, errors.New("be16 expects 1 arg")
		}
		value, err := evaluateExprArg(expr.GetArgs()[0], ctx)
		if err != nil {
			return evalValue{}, err
		}
		u64Value, err := value.asU64()
		if err != nil {
			return evalValue{}, err
		}
		if u64Value > 0xFFFF {
			return evalValue{}, errors.New("be16 overflow")
		}
		out := make([]byte, 2)
		binary.BigEndian.PutUint16(out, uint16(u64Value))
		return evalValue{bytes: out}, nil
	case "be32":
		if len(expr.GetArgs()) != 1 {
			return evalValue{}, errors.New("be32 expects 1 arg")
		}
		value, err := evaluateExprArg(expr.GetArgs()[0], ctx)
		if err != nil {
			return evalValue{}, err
		}
		u64Value, err := value.asU64()
		if err != nil {
			return evalValue{}, err
		}
		if u64Value > 0xFFFFFFFF {
			return evalValue{}, errors.New("be32 overflow")
		}
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(u64Value))
		return evalValue{bytes: out}, nil
	default:
		return evalValue{}, errors.New("unsupported expr op: ", expr.GetOp())
	}
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

func evaluateExprArg(arg *ExprArg, ctx *evalContext) (evalValue, error) {
	switch value := arg.GetValue().(type) {
	case *ExprArg_Bytes:
		return evalValue{bytes: append([]byte(nil), value.Bytes...)}, nil
	case *ExprArg_U64:
		return evalValue{u64: &value.U64}, nil
	case *ExprArg_Var:
		saved, ok := ctx.vars[value.Var]
		if !ok {
			return evalValue{}, errors.New("unknown variable: ", value.Var)
		}
		return evalValue{bytes: append([]byte(nil), saved...)}, nil
	case *ExprArg_Metadata:
		return evalValue{}, errors.New("metadata not implemented: ", value.Metadata)
	case *ExprArg_Expr:
		return evaluateExpr(value.Expr, ctx)
	default:
		return evalValue{}, errors.New("empty expr arg")
	}
}

func (v evalValue) asBytes() ([]byte, error) {
	if v.bytes != nil {
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

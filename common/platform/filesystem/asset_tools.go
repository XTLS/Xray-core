package filesystem

func DecodeVarint(buf []byte) (x uint64, n int) {
	for shift := uint(0); shift < 64; shift += 7 {
		if n >= len(buf) {
			return 0, 0
		}
		b := uint64(buf[n])
		n++
		x |= (b & 0x7F) << shift
		if (b & 0x80) == 0 {
			return x, n
		}
	}

	// The number is too large to represent in a 64-bit value.
	return 0, 0
}

func Find(data, code []byte) []byte {
	codeL := len(code)
	if codeL == 0 {
		return nil
	}
	for {
		dataL := len(data)
		if dataL < 2 {
			return nil
		}
		x, y := DecodeVarint(data[1:])
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

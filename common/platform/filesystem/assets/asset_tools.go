package assets

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

func Find(data, code []byte) (found []byte, startByte int) {
	codeL := len(code)
	if codeL == 0 {
		return nil, -1
	}

	base := data
	offset := 0

	for {
		dataL := len(data)
		if dataL < 2 {
			return nil, -1
		}

		x, y := DecodeVarint(data[1:])
		if x == 0 && y == 0 {
			return nil, -1
		}

		headL := 1 + y
		bodyL := int(x)

		if dataL < headL+bodyL {
			return nil, -1
		}

		// Move to body
		data = data[headL:]
		offset += headL

		// Check code match
		if int(data[1]) == codeL {
			match := true
			for i := 0; i < codeL; i++ {
				if data[2+i] != code[i] {
					match = false
					break
				}
			}
			if match {
				start := offset
				end := offset + bodyL
				return base[start:end], start
			}
		}

		// Advance to next record
		data = data[bodyL:]
		offset += bodyL

		if len(data) == 0 {
			return nil, -1
		}
	}
}

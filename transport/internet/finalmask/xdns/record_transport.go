package xdns

import "bytes"

const ipRecordHeaderSize = 2

func maxEncodedPayloadForType(rrType uint16) int {
	switch rrType {
	case RRTypeA:
		return maxEncodedPayloadA
	case RRTypeAAAA:
		return maxEncodedPayloadAAAA
	default:
		return maxEncodedPayloadTXT
	}
}

func rrDataSizeForType(rrType uint16) int {
	switch rrType {
	case RRTypeA:
		return 4
	case RRTypeAAAA:
		return 16
	default:
		return 0
	}
}

func payloadChunkSizeForType(rrType uint16) int {
	size := rrDataSizeForType(rrType)
	if size <= ipRecordHeaderSize {
		return 0
	}
	return size - ipRecordHeaderSize
}

func answersForPayload(question Question, ttl uint32, payload []byte) ([]RR, error) {
	switch question.Type {
	case RRTypeTXT:
		return []RR{
			{
				Name:  question.Name,
				Type:  question.Type,
				Class: question.Class,
				TTL:   ttl,
				Data:  EncodeRDataTXT(payload),
			},
		}, nil
	case RRTypeA, RRTypeAAAA:
		return ipAnswersForPayload(question, ttl, payload)
	default:
		return nil, ErrIntegerOverflow
	}
}

func ipAnswersForPayload(question Question, ttl uint32, payload []byte) ([]RR, error) {
	chunkSize := payloadChunkSizeForType(question.Type)
	rrDataSize := rrDataSizeForType(question.Type)
	if chunkSize == 0 || rrDataSize == 0 {
		return nil, ErrIntegerOverflow
	}

	numRecords := 1
	if len(payload) > 0 {
		numRecords = (len(payload) + chunkSize - 1) / chunkSize
	}
	if numRecords > 256 {
		return nil, ErrIntegerOverflow
	}

	answers := make([]RR, 0, numRecords)
	for i := 0; i < numRecords; i++ {
		offset := i * chunkSize
		n := len(payload) - offset
		if n < 0 {
			n = 0
		}
		if n > chunkSize {
			n = chunkSize
		}

		data := make([]byte, rrDataSize)
		data[0] = byte(i)
		data[1] = byte(n)
		copy(data[ipRecordHeaderSize:], payload[offset:offset+n])

		answers = append(answers, RR{
			Name:  question.Name,
			Type:  question.Type,
			Class: question.Class,
			TTL:   ttl,
			Data:  data,
		})
	}

	return answers, nil
}

func decodeResponsePayload(answers []RR) []byte {
	if len(answers) == 0 {
		return nil
	}

	switch answers[0].Type {
	case RRTypeTXT:
		if len(answers) != 1 {
			return nil
		}
		payload, err := DecodeRDataTXT(answers[0].Data)
		if err != nil {
			return nil
		}
		return payload
	case RRTypeA, RRTypeAAAA:
		return decodeIPAnswerPayload(answers, answers[0].Type)
	default:
		return nil
	}
}

func decodeIPAnswerPayload(answers []RR, rrType uint16) []byte {
	chunkSize := payloadChunkSizeForType(rrType)
	rrDataSize := rrDataSizeForType(rrType)
	if chunkSize == 0 || rrDataSize == 0 || len(answers) > 256 {
		return nil
	}

	parts := make([][]byte, len(answers))
	for _, answer := range answers {
		if answer.Type != rrType || len(answer.Data) != rrDataSize {
			return nil
		}
		idx := int(answer.Data[0])
		n := int(answer.Data[1])
		if idx >= len(answers) || n > chunkSize || parts[idx] != nil {
			return nil
		}

		part := make([]byte, n)
		copy(part, answer.Data[ipRecordHeaderSize:ipRecordHeaderSize+n])
		parts[idx] = part
	}

	var payload bytes.Buffer
	for _, part := range parts {
		if part == nil {
			return nil
		}
		payload.Write(part)
	}
	return payload.Bytes()
}

func computeMaxEncodedPayload(limit int) int {
	return computeMaxEncodedPayloadForType(limit, RRTypeTXT)
}

func computeMaxEncodedPayloadForType(limit int, rrType uint16) int {
	maxLengthName, err := NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1
		if n != 255 {
			panic("computeMaxEncodedPayload n != 255")
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &Message{
		Question: []Question{
			{
				Name:  maxLengthName,
				Type:  rrType,
				Class: ClassIN,
			},
		},
		Additional: []RR{
			{
				Name:  Name{},
				Type:  RRTypeOPT,
				Class: queryLimit,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, []domainSpec{{name: Name{[]byte{}}}})

	low := 0
	high := 32768
	if chunkSize := payloadChunkSizeForType(rrType); chunkSize > 0 {
		high = 256*chunkSize + 1
	}
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer, err = answersForPayload(query.Question[0], responseTTL, make([]byte, mid))
		if err != nil {
			panic(err)
		}
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

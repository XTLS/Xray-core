package bittorrent

import (
	"github.com/xtls/xray-core/common"
)

// The DHT speaks KRPC (BEP 5): bencoded dictionaries, one per UDP datagram.
// Only as much of bencode as it takes to validate the shape of a message is
// implemented here, since a sniffer cares about the framing, not the contents.

// bencodeMaxDepth bounds recursion on hostile input. Real KRPC messages nest
// three levels at most.
const bencodeMaxDepth = 8

// readString reads the bencode byte string at i, returning its content and the
// offset just past it.
func readString(b []byte, i int) ([]byte, int, bool) {
	colon := -1
	// a length of more than seven digits cannot describe a datagram
	for j := i; j < len(b) && j < i+8; j++ {
		if b[j] == ':' {
			colon = j
			break
		}
		if b[j] < '0' || b[j] > '9' {
			return nil, 0, false
		}
	}
	if colon <= i {
		return nil, 0, false
	}

	length := 0
	for _, d := range b[i:colon] {
		length = length*10 + int(d-'0')
	}

	end := colon + 1 + length
	if end > len(b) {
		return nil, 0, false
	}
	return b[colon+1 : end], end, true
}

// skipValue validates the bencode value at i and returns the offset just past it.
func skipValue(b []byte, i, depth int) (int, bool) {
	if depth > bencodeMaxDepth || i >= len(b) {
		return 0, false
	}

	switch c := b[i]; c {
	case 'i':
		j := i + 1
		if j < len(b) && b[j] == '-' {
			j++
		}
		digits := j
		for j < len(b) && b[j] >= '0' && b[j] <= '9' {
			j++
		}
		if j == digits || j >= len(b) || b[j] != 'e' {
			return 0, false
		}
		return j + 1, true
	case 'l':
		j := i + 1
		for j < len(b) && b[j] != 'e' {
			next, ok := skipValue(b, j, depth+1)
			if !ok {
				return 0, false
			}
			j = next
		}
		if j >= len(b) {
			return 0, false
		}
		return j + 1, true
	case 'd':
		j := i + 1
		for j < len(b) && b[j] != 'e' {
			// keys are always byte strings
			_, valueStart, ok := readString(b, j)
			if !ok {
				return 0, false
			}
			next, ok := skipValue(b, valueStart, depth+1)
			if !ok {
				return 0, false
			}
			j = next
		}
		if j >= len(b) {
			return 0, false
		}
		return j + 1, true
	default:
		if c < '0' || c > '9' {
			return 0, false
		}
		_, end, ok := readString(b, i)
		return end, ok
	}
}

// hasNodeID reports whether a bencoded dictionary carries the 20 byte "id" that
// every KRPC query and response has to name.
func hasNodeID(d []byte) bool {
	if len(d) == 0 || d[0] != 'd' {
		return false
	}

	i := 1
	for i < len(d) && d[i] != 'e' {
		key, valueStart, ok := readString(d, i)
		if !ok {
			return false
		}
		valueEnd, ok := skipValue(d, valueStart, 1)
		if !ok {
			return false
		}
		if string(key) == "id" {
			id, _, ok := readString(d, valueStart)
			return ok && len(id) == 20
		}
		i = valueEnd
	}

	return false
}

// SniffDHT matches a KRPC message of the BitTorrent DHT (BEP 5).
func SniffDHT(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	// every KRPC message is a bencoded dictionary
	if b[0] != 'd' {
		return nil, errNotBittorrent
	}

	var msgType, txID, method, args, resp, errList []byte

	i := 1
	for i < len(b) && b[i] != 'e' {
		key, valueStart, ok := readString(b, i)
		if !ok {
			return nil, errNotBittorrent
		}
		valueEnd, ok := skipValue(b, valueStart, 1)
		if !ok {
			return nil, errNotBittorrent
		}
		if len(key) == 1 {
			switch key[0] {
			// a value of the wrong kind leaves the field empty, which the
			// checks below reject
			case 'y':
				msgType, _, _ = readString(b, valueStart)
			case 't':
				txID, _, _ = readString(b, valueStart)
			case 'q':
				method, _, _ = readString(b, valueStart)
			case 'a':
				args = b[valueStart:valueEnd]
			case 'r':
				resp = b[valueStart:valueEnd]
			case 'e':
				errList = b[valueStart:valueEnd]
			}
		}
		i = valueEnd
	}

	// the loop stops on the closing 'e', which has to be the last byte
	if i+1 != len(b) {
		return nil, errNotBittorrent
	}

	if len(msgType) != 1 || len(txID) == 0 {
		return nil, errNotBittorrent
	}

	switch msgType[0] {
	case 'q': // query: a method name, and arguments naming the sender
		if len(method) == 0 || !hasNodeID(args) {
			return nil, errNotBittorrent
		}
	case 'r': // response: the answering node names itself
		if !hasNodeID(resp) {
			return nil, errNotBittorrent
		}
	case 'e': // error: a list holding a code and a message
		if len(errList) == 0 || errList[0] != 'l' {
			return nil, errNotBittorrent
		}
	default:
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

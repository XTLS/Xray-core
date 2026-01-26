//go:build gofuzz
// +build gofuzz

// Fuzzing driver for https://github.com/dvyukov/go-fuzz.
// 	go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
// 	$GOPATH/bin/go-fuzz-build
// 	$GOPATH/bin/go-fuzz
//
// Related link: https://blog.cloudflare.com/dns-parser-meet-go-fuzzer/

package dns

func Fuzz(data []byte) int {
	msg, err := MessageFromWireFormat(data)
	if err != nil {
		return 0
	}
	_, err = msg.WireFormat()
	if err != nil {
		panic(err)
	}
	return 1 // prioritize this input
}

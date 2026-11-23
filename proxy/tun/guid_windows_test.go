//go:build windows

package tun

import (
	"crypto/md5"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestAdapterGUID(t *testing.T) {
	// a configured GUID has to be the adapter GUID the text names: the groups
	// are field values, not the bytes of the text in order
	guid, err := adapterGUID("xray0", "01020304-0506-0708-090a-0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}
	want := windows.GUID{
		Data1: 0x01020304,
		Data2: 0x0506,
		Data3: 0x0708,
		Data4: [8]byte{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}
	if *guid != want {
		t.Errorf("adapterGUID = %+v, want %+v", *guid, want)
	}
	// the same struct Windows builds from that text, and the text Windows shows
	// for it
	if fromText, err := windows.GUIDFromString("{01020304-0506-0708-090A-0B0C0D0E0F10}"); err != nil {
		t.Fatal(err)
	} else if *guid != fromText {
		t.Errorf("adapterGUID = %s, want %s", guid.String(), fromText.String())
	}
	if got, want := guid.String(), "{01020304-0506-0708-090A-0B0C0D0E0F10}"; got != want {
		t.Errorf("adapterGUID = %s, want %s", got, want)
	}

	// without one, the bytes of the MD5 of the name, as they always were; that
	// GUID is never read back as text, so its byte order does not matter
	guid, err = adapterGUID("xray0", "")
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum([]byte("xray0"))
	if got := unsafe.Slice((*byte)(unsafe.Pointer(guid)), 16); string(got) != string(sum[:]) {
		t.Errorf("adapterGUID = %x, want %x", got, sum)
	}

	if _, err := adapterGUID("xray0", "xray0"); err == nil {
		t.Error("an invalid guid was accepted")
	}
}

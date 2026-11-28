package xmc

import (
	"strings"
	"testing"
)

// TestProtocolTablePinsRegistrationOrder pins every id XMC uses against the
// source it came from, so that changing a row is a conscious edit and not a
// side effect of a refactor:
//
//   - 767..775: minecraft-data data/pc/<version>/protocol.json, keyed by the
//     packet name in the same order LoginProtocols and ConfigurationProtocols
//     register them;
//   - 776..777: the official 26.2 and 26.3 jars.
func TestProtocolTablePinsRegistrationOrder(t *testing.T) {
	wantLogin := loginPacketIDs{
		serverboundLoginStart:        0x00,
		serverboundKey:               0x01,
		serverboundCustomQueryAnswer: 0x02,
		serverboundLoginAcknowledged: 0x03,
		serverboundCookieResponse:    0x04,

		clientboundLoginDisconnect:  0x00,
		clientboundHello:            0x01,
		clientboundLoginFinished:    0x02,
		clientboundLoginCompression: 0x03,
		clientboundCustomQuery:      0x04,
		clientboundCookieRequest:    0x05,
	}
	wantConfiguration := configurationPacketIDs{
		serverboundClientInformation: 0x00,
		serverboundCookieResponse:    0x01,
		serverboundCustomPayload:     0x02,
		serverboundKeepAlive:         0x04,
		serverboundPong:              0x05,

		clientboundCookieRequest: 0x00,
		clientboundCustomPayload: 0x01,
		clientboundDisconnect:    0x02,
		clientboundKeepAlive:     0x04,
		clientboundPing:          0x05,
	}

	for _, version := range protocolVersions {
		if version.login != wantLogin {
			t.Fatalf("%s (%d): login ids = %+v, want %+v", version.name, version.number, version.login, wantLogin)
		}
		if version.configuration != wantConfiguration {
			t.Fatalf("%s (%d): configuration ids = %+v, want %+v", version.name, version.number, version.configuration, wantConfiguration)
		}
	}
}

// TestProtocolTableCoverage checks the table is a contiguous, ordered run of
// the releases XMC supports, and that the newest row is the default.
func TestProtocolTableCoverage(t *testing.T) {
	if len(protocolVersions) == 0 {
		t.Fatal("empty protocol table")
	}
	for i, version := range protocolVersions {
		want := Varint(767 + i)
		if version.number != want {
			t.Fatalf("row %d is protocol %d, want %d", i, version.number, want)
		}
		if version.name == "" {
			t.Fatalf("row %d (%d) has no release name", i, version.number)
		}
		if version.loginFinishedSessionID != (version.number >= 776) {
			t.Fatalf("%s (%d): loginFinishedSessionID = %v", version.name, version.number, version.loginFinishedSessionID)
		}
	}

	if latestProtocolVersion.number != 777 || latestProtocolVersion.name != "26.3" {
		t.Fatalf("latest row = %s (%d), want 26.3 (777)", latestProtocolVersion.name, latestProtocolVersion.number)
	}
	if !latestProtocolVersion.loginFinishedSessionID {
		t.Fatal("26.3 must carry the Login Finished session id")
	}
	if _, ok := protocolVersionByNumber(776); !ok {
		t.Fatal("26.2 row is missing")
	}
	if _, ok := protocolVersionByNumber(775); !ok {
		t.Fatal("26.1 row is missing")
	}
}

func TestProtocolVersionByNumberRejectsUnknown(t *testing.T) {
	for _, number := range []Varint{0, 1, 766, 778, 9999} {
		if _, ok := protocolVersionByNumber(number); ok {
			t.Fatalf("protocol %d should not be in the table", number)
		}
	}
}

func TestProtocolVersionRange(t *testing.T) {
	got := protocolVersionRange()
	for _, want := range []string{"767 (1.21.1)", "777 (26.3)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("range %q does not contain %q", got, want)
		}
	}
}

// TestLoginRejectReason checks the vanilla split at 1.20.5 (754): older clients
// are told to update, newer ones that the server is incompatible.
func TestLoginRejectReason(t *testing.T) {
	if got := loginRejectReason(700); !strings.Contains(got, "multiplayer.disconnect.outdated_client") {
		t.Fatalf("old client reason = %s", got)
	}
	for _, number := range []Varint{754, 775, 778} {
		got := loginRejectReason(number)
		if !strings.Contains(got, "multiplayer.disconnect.incompatible") {
			t.Fatalf("protocol %d reason = %s", number, got)
		}
		if !strings.Contains(got, `"with":["26.3"]`) {
			t.Fatalf("protocol %d reason has no version argument: %s", number, got)
		}
	}
}

// TestStatusResponse pins the status JSON shape a vanilla server builds: a
// collapsed literal description, player counts with an empty sample, and the
// version it speaks.
func TestStatusResponse(t *testing.T) {
	got := statusResponse(latestProtocolVersion)
	want := `{"description":"A Minecraft Server","players":{"max":20,"online":0,"sample":[]},"version":{"name":"26.3","protocol":777},"enforcesSecureChat":true}`
	if got != want {
		t.Fatalf("status = %s\nwant   %s", got, want)
	}
	if got := statusResponse(protocolVersions[0]); !strings.Contains(got, `"version":{"name":"1.21.1","protocol":767}`) {
		t.Fatalf("1.21.1 status = %s", got)
	}
}

func TestValidPlayerName(t *testing.T) {
	for _, name := range []string{"Notch", "a", "Player_123", "Player.Name-1", strings.Repeat("a", 16)} {
		if !validPlayerName(name) {
			t.Fatalf("%q should be a valid 26.x player name", name)
		}
	}
	// 26.x only rejects lengths above sixteen and bytes outside printable ASCII:
	// spaces and the old "letters, digits, underscore" restriction are gone.
	for _, name := range []string{strings.Repeat("a", 17), "name with space", "tab\tname", "high\x7f", "unicode\u00e9"} {
		if validPlayerName(name) {
			t.Fatalf("%q should be rejected", name)
		}
	}
}

func TestGameVersion(t *testing.T) {
	version, err := (&Config{}).gameVersion()
	if err != nil || version.number != latestProtocolVersion.number {
		t.Fatalf("default version = %v, %v", version.number, err)
	}

	version, err = (&Config{ProtocolVersion: 775}).gameVersion()
	if err != nil || version.number != 775 {
		t.Fatalf("configured version = %v, %v", version.number, err)
	}

	if _, err = (&Config{ProtocolVersion: 778}).gameVersion(); err == nil || !strings.Contains(err.Error(), "unsupported protocol version 778") {
		t.Fatalf("unknown version error = %v", err)
	}
}

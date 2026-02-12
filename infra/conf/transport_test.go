package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	finalsudoku "github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestSocketConfig(t *testing.T) {
	createParser := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(SocketConfig)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}

	// test "tcpFastOpen": true, queue length 256 is expected. other parameters are tested here too
	expectedOutput := &internet.SocketConfig{
		Mark:           1,
		Tfo:            256,
		DomainStrategy: internet.DomainStrategy_USE_IP,
		DialerProxy:    "tag",
		HappyEyeballs:  &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"mark": 1,
				"tcpFastOpen": true,
				"domainStrategy": "UseIP",
				"dialerProxy": "tag"
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 256 {
		t.Fatalf("unexpected parsed TFO value, which should be 256")
	}

	// test "tcpFastOpen": false, disabled TFO is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           -1,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": false
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 0 {
		t.Fatalf("unexpected parsed TFO value, which should be 0")
	}

	// test "tcpFastOpen": 65535, queue length 65535 is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           65535,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": 65535
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 65535 {
		t.Fatalf("unexpected parsed TFO value, which should be 65535")
	}

	// test "tcpFastOpen": -65535, disable TFO is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           -65535,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": -65535
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 0 {
		t.Fatalf("unexpected parsed TFO value, which should be 0")
	}

	// test "tcpFastOpen": 0, no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": 0
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}

	// test omit "tcpFastOpen", no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input:  `{}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}

	// test "tcpFastOpen": null, no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": null
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}
}

func TestFinalMaskSudokuBDD(t *testing.T) {
	t.Run("GivenSudokuMaskConfigWhenBuildingStreamSettingsThenTcpAndUdpMasksAreSerialized", func(t *testing.T) {
		cfgJSON := `{
			"network": "tcp",
			"finalmask": {
				"tcp": [
					{
						"type": "sudoku",
						"settings": {
							"password": "bdd-sudoku",
							"ascii": "prefer_entropy",
							"customTable": "xpxvvpvv",
							"paddingMin": 2,
							"paddingMax": 7
						}
					}
				],
				"udp": [
					{
						"type": "sudoku",
						"settings": {
							"password": "bdd-sudoku",
							"ascii": "prefer_ascii"
						}
					}
				]
			}
		}`

		conf := new(StreamConfig)
		if err := json.Unmarshal([]byte(cfgJSON), conf); err != nil {
			t.Fatal(err)
		}

		built, err := conf.Build()
		if err != nil {
			t.Fatal(err)
		}
		if len(built.Tcpmasks) != 1 {
			t.Fatalf("expected 1 tcp mask, got %d", len(built.Tcpmasks))
		}
		if len(built.Udpmasks) != 1 {
			t.Fatalf("expected 1 udp mask, got %d", len(built.Udpmasks))
		}

		tcpMask, err := built.Tcpmasks[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		tcpSudoku, ok := tcpMask.(*finalsudoku.Config)
		if !ok {
			t.Fatalf("unexpected tcp mask type: %T", tcpMask)
		}
		if tcpSudoku.GetCustomTable() != "xpxvvpvv" {
			t.Fatalf("unexpected custom table: %s", tcpSudoku.GetCustomTable())
		}
		if tcpSudoku.GetPaddingMin() != 2 || tcpSudoku.GetPaddingMax() != 7 {
			t.Fatalf("unexpected padding range: %d-%d", tcpSudoku.GetPaddingMin(), tcpSudoku.GetPaddingMax())
		}

		udpMask, err := built.Udpmasks[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		udpSudoku, ok := udpMask.(*finalsudoku.Config)
		if !ok {
			t.Fatalf("unexpected udp mask type: %T", udpMask)
		}
		if udpSudoku.GetAscii() != "prefer_ascii" {
			t.Fatalf("unexpected udp ascii mode: %s", udpSudoku.GetAscii())
		}
	})

	t.Run("GivenLegacySudokuKeysWhenBuildingThenLegacyFieldsAreAccepted", func(t *testing.T) {
		cfgJSON := `{
			"network": "tcp",
			"finalmask": {
				"tcp": [
					{
						"type": "sudoku",
						"settings": {
							"password": "bdd-sudoku",
							"ascii": "prefer_entropy",
							"custom_table": "vxpvxvvp",
							"padding_min": 1,
							"padding_max": 3
						}
					}
				]
			}
		}`

		conf := new(StreamConfig)
		if err := json.Unmarshal([]byte(cfgJSON), conf); err != nil {
			t.Fatal(err)
		}

		built, err := conf.Build()
		if err != nil {
			t.Fatal(err)
		}
		if len(built.Tcpmasks) != 1 {
			t.Fatalf("expected 1 tcp mask, got %d", len(built.Tcpmasks))
		}

		tcpMask, err := built.Tcpmasks[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		sudokuMask, ok := tcpMask.(*finalsudoku.Config)
		if !ok {
			t.Fatalf("unexpected mask type: %T", tcpMask)
		}
		if sudokuMask.GetCustomTable() != "vxpvxvvp" {
			t.Fatalf("unexpected legacy custom table parse result: %s", sudokuMask.GetCustomTable())
		}
		if sudokuMask.GetPaddingMin() != 1 || sudokuMask.GetPaddingMax() != 3 {
			t.Fatalf("unexpected legacy padding parse result: %d-%d", sudokuMask.GetPaddingMin(), sudokuMask.GetPaddingMax())
		}

		// keep a stable serialization check for regression visibility.
		if _, err := protojson.Marshal(sudokuMask); err != nil {
			t.Fatal(err)
		}
	})
}

package xmc

import (
	"time"
)

// Length and write-boundary templates come from controlled Minecraft 26.1.2
// logins. Timing deliberately uses broad random bands that preserve only the
// rough ordering of short and long phases; it does not replay captured delays.
var startupPaddingSchedule2612 = []paddingTurn{
	{
		direction: paddingClientToServer,
		variants: []paddingVariant{
			paddingVariantFromChunks(2, 26, 16),
		},
	},
	{
		direction: paddingServerToClient,
		variants: []paddingVariant{
			paddingVariantFromChunks(26, 21, 25),
		},
		startDelay: millisecondRange(0, 20),
	},
	{
		direction: paddingClientToServer,
		variants: []paddingVariant{
			paddingVariantFromChunks(25),
		},
		startDelay: millisecondRange(2, 22),
	},
	{
		direction: paddingServerToClient,
		variants: []paddingVariant{
			registryPaddingVariant(),
		},
		startDelay: millisecondRange(20, 50),
	},
	{
		direction: paddingClientToServer,
		variants: []paddingVariant{
			paddingVariantFromChunks(2),
		},
		startDelay: millisecondRange(10, 35),
	},
	{
		direction: paddingServerToClient,
		variants: []paddingVariant{
			playStartPaddingVariant(4941, 252, 259, 267, 268, 251, 303, 259, 264, 54, 346),
			playStartPaddingVariant(4941, 262, 284, 272, 260, 260, 313, 264, 151, 224, 207, 215, 224, 390),
			playStartPaddingVariant(4941, 257, 272, 275, 260, 260, 313, 283, 274, 226, 207, 230, 215, 204, 221, 352),
			playStartPaddingVariant(4941, 259, 272, 288, 260, 260, 311, 270, 70, 236, 223, 201, 210, 352),
			playStartPaddingVariant(4941, 255, 269, 277, 263, 260, 136, 207, 210, 232, 325),
			playStartPaddingVariant(4941, 259, 270, 274, 263, 258, 327, 170, 210, 375),
			playStartPaddingVariant(4941, 257, 275, 291, 260, 260, 325, 269, 70, 230, 226, 207, 221, 352),
			playStartPaddingVariant(4941, 252, 273, 262, 252, 254, 306, 93),
			playStartPaddingVariant(4941, 273, 270, 269, 258, 256, 322, 221, 207, 215, 438),
			playStartPaddingVariant(4941, 259, 275, 274, 250, 258, 308, 267, 154, 233, 209, 207, 213, 393),
			playStartPaddingVariant(4941, 254, 267, 272, 260, 253, 311, 167, 204, 232, 207, 481, 8),
			playStartPaddingVariant(4941, 259, 269, 272, 261, 313, 207, 213, 500, 19),
			playStartPaddingVariant(4941, 262, 269, 274, 263, 274, 311, 270, 242, 210, 229, 221, 210, 431),
			playStartPaddingVariant(4941, 259, 265, 277, 263, 277, 316, 269, 156, 204, 210, 226, 207, 413),
			playStartPaddingVariant(4941, 215, 251, 249, 317, 260, 270, 249, 52),
			playStartPaddingVariant(4941, 224, 263, 277, 316, 267, 272, 260, 138, 230, 226, 207, 204, 352),
			playStartPaddingVariant(4941, 221, 258, 263, 319, 269, 288, 263, 136, 204, 210, 220, 207, 378),
			playStartPaddingVariant(4941, 221, 258, 260, 316, 273, 291, 226, 204, 229, 213, 489, 8),
			playStartPaddingVariant(4941, 238, 260, 261, 306, 272, 277, 260, 224, 241, 212, 207, 204, 393),
			playStartPaddingVariant(4941, 224, 260, 260, 309, 272, 277, 277, 138, 207, 207, 212, 241, 352),
		},
		startDelay: millisecondRange(35, 50),
	},
}

// These turns cover the finite Play-state tail through the client's
// player_loaded packet. Bounds are the observed per-turn minima and maxima
// across 20 controlled 26.1.2 logins; payload bytes remain opaque padding.
var playJoinPaddingSchedule2612 = []paddingTurn{
	clientPlayPaddingTurn(6, 883),
	serverPlayPaddingTurn(346, 58638),
	clientPlayPaddingTurn(6, 887),
	serverPlayPaddingTurn(388, 61077),
	clientPlayPaddingTurn(2, 50),
	serverPlayPaddingTurn(575, 65584),
	clientPlayPaddingTurn(6, 45),
	serverPlayPaddingTurn(86, 63563),
	clientPlayPaddingTurn(2, 44),
	serverPlayPaddingTurn(42, 51983),
	clientPlayPaddingTurn(2, 851),
	serverPlayPaddingTurn(309, 25083),
	clientPlayPaddingTurn(2, 19),
	serverPlayPaddingTurn(74, 63885),
	clientPlayPaddingTurn(8, 24),
	serverPlayPaddingTurn(30, 66128),
	clientPlayPaddingTurn(2, 19),
	serverPlayPaddingTurn(26, 35818),
	clientPlayPaddingTurn(6, 19),
	serverPlayPaddingTurn(35, 59407),
	clientPlayPaddingTurn(6, 19),
	serverPlayPaddingTurn(37, 65328),
	clientPlayPaddingTurn(2, 19),
	serverPlayPaddingTurn(26, 60622),
	clientPlayPaddingTurn(6, 19),
	serverPlayPaddingTurn(11, 60808),
	clientPlayPaddingTurn(8, 43),
	serverPlayPaddingTurn(55, 62027),
	clientPlayPaddingTurn(2, 19),
	serverPlayPaddingTurn(427, 65622),
	clientPlayPaddingTurn(5, 19),
	serverPlayPaddingTurn(35, 59401),
	clientPlayPaddingTurn(6, 19),
}

type paddingLengthRange2612 struct {
	minimum int
	maximum int
}

type serverPlayLengthBranches2612 struct {
	small paddingLengthRange2612
	large paddingLengthRange2612
}

var serverPlayBranches2612 = []serverPlayLengthBranches2612{
	{small: paddingLengthRange2612{346, 18812}, large: paddingLengthRange2612{51702, 58638}},
	{small: paddingLengthRange2612{388, 20689}, large: paddingLengthRange2612{51445, 61077}},
	{small: paddingLengthRange2612{575, 20915}, large: paddingLengthRange2612{41428, 65584}},
	{small: paddingLengthRange2612{86, 2772}, large: paddingLengthRange2612{41428, 63563}},
	{small: paddingLengthRange2612{42, 26813}, large: paddingLengthRange2612{51983, 51983}},
	{small: paddingLengthRange2612{309, 19484}, large: paddingLengthRange2612{24837, 25083}},
	{small: paddingLengthRange2612{74, 40686}, large: paddingLengthRange2612{63885, 63885}},
	{small: paddingLengthRange2612{30, 44114}, large: paddingLengthRange2612{66128, 66128}},
	{small: paddingLengthRange2612{26, 1464}, large: paddingLengthRange2612{9941, 35818}},
	{small: paddingLengthRange2612{35, 42885}, large: paddingLengthRange2612{52194, 59407}},
	{small: paddingLengthRange2612{37, 47553}, large: paddingLengthRange2612{61765, 65328}},
	{small: paddingLengthRange2612{26, 1121}, large: paddingLengthRange2612{16162, 60622}},
	{small: paddingLengthRange2612{11, 45629}, large: paddingLengthRange2612{60808, 60808}},
	{small: paddingLengthRange2612{55, 10035}, large: paddingLengthRange2612{30237, 62027}},
	{small: paddingLengthRange2612{427, 52536}, large: paddingLengthRange2612{64014, 65622}},
	{small: paddingLengthRange2612{35, 22708}, large: paddingLengthRange2612{38987, 59401}},
}

// Each mask preserves only the small/large branch order from one baseline
// login. Actual lengths and timing are selected randomly inside each branch.
var serverPlayBranchMasks2612 = []uint32{
	0x011c, 0x090a, 0x0821, 0xe921, 0x2102,
	0x0844, 0xa101, 0x1106, 0x2e00, 0xab01,
	0xe900, 0xac01, 0xab01, 0x8b80, 0x0808,
	0x2001, 0x0901, 0x000a, 0x2c01, 0x0801,
}

type clientPlayBurst2612 struct {
	playIndex int
	regular   paddingLengthRange2612
	burst     paddingLengthRange2612
}

var clientPlayBursts2612 = []clientPlayBurst2612{
	{playIndex: 0, regular: paddingLengthRange2612{6, 44}, burst: paddingLengthRange2612{877, 883}},
	{playIndex: 2, regular: paddingLengthRange2612{6, 45}, burst: paddingLengthRange2612{884, 887}},
	{playIndex: 10, regular: paddingLengthRange2612{2, 19}, burst: paddingLengthRange2612{851, 851}},
}

// The 20 samples placed the one client initialization burst in these slots.
var clientPlayBurstChoices2612 = []int{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1,
	2,
}

var paddingSchedule2612 = buildPaddingSchedule2612()

func buildPaddingSchedule2612() []paddingTurn {
	schedule := make([]paddingTurn, 0, len(startupPaddingSchedule2612)+len(playJoinPaddingSchedule2612))
	schedule = append(schedule, startupPaddingSchedule2612...)
	schedule = append(schedule, playJoinPaddingSchedule2612...)
	return schedule
}

func clientPlayPaddingTurn(minimum, maximum int) paddingTurn {
	return paddingTurn{
		direction:        paddingClientToServer,
		minLength:        minimum,
		maxLength:        maximum,
		startDelay:       millisecondRange(1, 30),
		writeChunkLength: 1024,
	}
}

func serverPlayPaddingTurn(minimum, maximum int) paddingTurn {
	return paddingTurn{
		direction:           paddingServerToClient,
		minLength:           minimum,
		maxLength:           maximum,
		startDelay:          millisecondRange(1, 45),
		chunkDelay:          millisecondRange(1, 4),
		writeChunkMinLength: 32 * 1024,
		writeChunkLength:    maxPaddingChunkLength,
	}
}

func newClientPaddingSchedule2612() ([]paddingTurn, error) {
	choice, err := randomPaddingIndex(len(clientPlayBurstChoices2612))
	if err != nil {
		return nil, err
	}
	selectedBurst := clientPlayBurstChoices2612[choice]
	schedule := append([]paddingTurn(nil), paddingSchedule2612...)
	for i, burst := range clientPlayBursts2612 {
		lengthRange := burst.regular
		if i == selectedBurst {
			lengthRange = burst.burst
		}
		turn := &schedule[len(startupPaddingSchedule2612)+burst.playIndex]
		turn.sendMinLength = lengthRange.minimum
		turn.sendMaxLength = lengthRange.maximum
	}
	return schedule, nil
}

type paddingPause struct {
	chunk int
	delay paddingDelayRange
}

func paddingVariantFromChunks(chunks ...int) paddingVariant {
	return paddingVariant{chunks: chunks}
}

func pacedPaddingVariant(chunks []int, pauses ...paddingPause) paddingVariant {
	delays := make([]paddingDelayRange, len(chunks))
	for _, pause := range pauses {
		if pause.chunk < 0 || pause.chunk >= len(delays) {
			panic("xmc: padding pause index is outside its chunk template")
		}
		delays[pause.chunk] = pause.delay
	}
	return paddingVariant{chunks: chunks, delays: delays}
}

func registryPaddingVariant() paddingVariant {
	return pacedPaddingVariant(
		[]int{1590, 226, 329, 229, 186, 151, 78, 81, 79, 235, 67, 67, 78, 71, 82, 74, 982, 117, 1118, 1038, 970, 400, 239, 49, 50, 95, 65, 104, 32320, 2},
		paddingPause{28, millisecondRange(1, 4)},
		paddingPause{29, millisecondRange(44, 61)},
	)
}

func playStartPaddingVariant(chunks ...int) paddingVariant {
	if len(chunks) < 2 {
		panic("xmc: play start padding variant needs at least two chunks")
	}
	return pacedPaddingVariant(
		chunks,
		paddingPause{len(chunks) / 2, millisecondRange(1, 5)},
		paddingPause{len(chunks) - 1, millisecondRange(9, 20)},
	)
}

func millisecondRange(minimum, maximum int) paddingDelayRange {
	return paddingDelayRange{
		min: time.Duration(minimum) * time.Millisecond,
		max: time.Duration(maximum) * time.Millisecond,
	}
}

func newServerPaddingSchedule2612() ([]paddingTurn, error) {
	schedule := append([]paddingTurn(nil), paddingSchedule2612...)
	profileIndex, err := randomPaddingIndex(len(serverPlayBranchMasks2612))
	if err != nil {
		return nil, err
	}
	profile := serverPlayBranchMasks2612[profileIndex]
	for i, branches := range serverPlayBranches2612 {
		lengthRange := branches.small
		if profile&(1<<i) != 0 {
			lengthRange = branches.large
		}
		turn := &schedule[len(startupPaddingSchedule2612)+1+i*2]
		turn.sendMinLength = lengthRange.minimum
		turn.sendMaxLength = lengthRange.maximum
	}
	return schedule, nil
}

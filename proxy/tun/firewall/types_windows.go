/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import "golang.org/x/sys/windows"

const (
	anysizeArray = 1 // ANYSIZE_ARRAY defined in winnt.h

	wtFwpBitmapArray64_Size = 8

	wtFwpByteArray16_Size = 16

	wtFwpByteArray6_Size = 6

	wtFwpmAction0_Size              = 20
	wtFwpmAction0_filterType_Offset = 4

	wtFwpV4AddrAndMask_Size        = 8
	wtFwpV4AddrAndMask_mask_Offset = 4

	wtFwpV6AddrAndMask_Size                = 17
	wtFwpV6AddrAndMask_prefixLength_Offset = 16
)

type wtFwpActionFlag uint32

const (
	cFWP_ACTION_FLAG_TERMINATING     wtFwpActionFlag = 0x00001000
	cFWP_ACTION_FLAG_NON_TERMINATING wtFwpActionFlag = 0x00002000
	cFWP_ACTION_FLAG_CALLOUT         wtFwpActionFlag = 0x00004000
)

// FWP_ACTION_TYPE defined in fwptypes.h
type wtFwpActionType uint32

const (
	cFWP_ACTION_BLOCK               wtFwpActionType = wtFwpActionType(0x00000001 | cFWP_ACTION_FLAG_TERMINATING)
	cFWP_ACTION_PERMIT              wtFwpActionType = wtFwpActionType(0x00000002 | cFWP_ACTION_FLAG_TERMINATING)
	cFWP_ACTION_CALLOUT_TERMINATING wtFwpActionType = wtFwpActionType(0x00000003 | cFWP_ACTION_FLAG_CALLOUT | cFWP_ACTION_FLAG_TERMINATING)
	cFWP_ACTION_CALLOUT_INSPECTION  wtFwpActionType = wtFwpActionType(0x00000004 | cFWP_ACTION_FLAG_CALLOUT | cFWP_ACTION_FLAG_NON_TERMINATING)
	cFWP_ACTION_CALLOUT_UNKNOWN     wtFwpActionType = wtFwpActionType(0x00000005 | cFWP_ACTION_FLAG_CALLOUT)
	cFWP_ACTION_CONTINUE            wtFwpActionType = wtFwpActionType(0x00000006 | cFWP_ACTION_FLAG_NON_TERMINATING)
	cFWP_ACTION_NONE                wtFwpActionType = 0x00000007
	cFWP_ACTION_NONE_NO_MATCH       wtFwpActionType = 0x00000008
	cFWP_ACTION_BITMAP_INDEX_SET    wtFwpActionType = 0x00000009
)

// FWP_BYTE_BLOB defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwp_byte_blob_)
type wtFwpByteBlob struct {
	size uint32
	data *uint8
}

// FWP_MATCH_TYPE defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ne-fwptypes-fwp_match_type_)
type wtFwpMatchType uint32

const (
	cFWP_MATCH_EQUAL                  wtFwpMatchType = 0
	cFWP_MATCH_GREATER                wtFwpMatchType = cFWP_MATCH_EQUAL + 1
	cFWP_MATCH_LESS                   wtFwpMatchType = cFWP_MATCH_GREATER + 1
	cFWP_MATCH_GREATER_OR_EQUAL       wtFwpMatchType = cFWP_MATCH_LESS + 1
	cFWP_MATCH_LESS_OR_EQUAL          wtFwpMatchType = cFWP_MATCH_GREATER_OR_EQUAL + 1
	cFWP_MATCH_RANGE                  wtFwpMatchType = cFWP_MATCH_LESS_OR_EQUAL + 1
	cFWP_MATCH_FLAGS_ALL_SET          wtFwpMatchType = cFWP_MATCH_RANGE + 1
	cFWP_MATCH_FLAGS_ANY_SET          wtFwpMatchType = cFWP_MATCH_FLAGS_ALL_SET + 1
	cFWP_MATCH_FLAGS_NONE_SET         wtFwpMatchType = cFWP_MATCH_FLAGS_ANY_SET + 1
	cFWP_MATCH_EQUAL_CASE_INSENSITIVE wtFwpMatchType = cFWP_MATCH_FLAGS_NONE_SET + 1
	cFWP_MATCH_NOT_EQUAL              wtFwpMatchType = cFWP_MATCH_EQUAL_CASE_INSENSITIVE + 1
	cFWP_MATCH_PREFIX                 wtFwpMatchType = cFWP_MATCH_NOT_EQUAL + 1
	cFWP_MATCH_NOT_PREFIX             wtFwpMatchType = cFWP_MATCH_PREFIX + 1
	cFWP_MATCH_TYPE_MAX               wtFwpMatchType = cFWP_MATCH_NOT_PREFIX + 1
)

// FWPM_ACTION0 defined in fwpmtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_action0_)
type wtFwpmAction0 struct {
	_type      wtFwpActionType
	filterType windows.GUID // Windows type: GUID
}

// Defined in fwpmu.h. 4cd62a49-59c3-4969-b7f3-bda5d32890a4
var cFWPM_CONDITION_IP_LOCAL_INTERFACE = windows.GUID{
	Data1: 0x4cd62a49,
	Data2: 0x59c3,
	Data3: 0x4969,
	Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4},
}

// Defined in fwpmu.h. b235ae9a-1d64-49b8-a44c-5ff3d9095045
var cFWPM_CONDITION_IP_REMOTE_ADDRESS = windows.GUID{
	Data1: 0xb235ae9a,
	Data2: 0x1d64,
	Data3: 0x49b8,
	Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
}

// Defined in fwpmu.h. 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
var cFWPM_CONDITION_IP_PROTOCOL = windows.GUID{
	Data1: 0x3971ef2b,
	Data2: 0x623e,
	Data3: 0x4f9a,
	Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
}

// Defined in fwpmu.h. 0c1ba1af-5765-453f-af22-a8f791ac775b
var cFWPM_CONDITION_IP_LOCAL_PORT = windows.GUID{
	Data1: 0x0c1ba1af,
	Data2: 0x5765,
	Data3: 0x453f,
	Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
}

// Defined in fwpmu.h. c35a604d-d22b-4e1a-91b4-68f674ee674b
var cFWPM_CONDITION_IP_REMOTE_PORT = windows.GUID{
	Data1: 0xc35a604d,
	Data2: 0xd22b,
	Data3: 0x4e1a,
	Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
}

// Defined in fwpmu.h. d78e1e87-8644-4ea5-9437-d809ecefc971
var cFWPM_CONDITION_ALE_APP_ID = windows.GUID{
	Data1: 0xd78e1e87,
	Data2: 0x8644,
	Data3: 0x4ea5,
	Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
}

// af043a0a-b34d-4f86-979c-c90371af6e66
var cFWPM_CONDITION_ALE_USER_ID = windows.GUID{
	Data1: 0xaf043a0a,
	Data2: 0xb34d,
	Data3: 0x4f86,
	Data4: [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66},
}

// d9ee00de-c1ef-4617-bfe3-ffd8f5a08957
var cFWPM_CONDITION_IP_LOCAL_ADDRESS = windows.GUID{
	Data1: 0xd9ee00de,
	Data2: 0xc1ef,
	Data3: 0x4617,
	Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57},
}

var (
	cFWPM_CONDITION_ICMP_TYPE = cFWPM_CONDITION_IP_LOCAL_PORT
	cFWPM_CONDITION_ICMP_CODE = cFWPM_CONDITION_IP_REMOTE_PORT
)

// 7bc43cbf-37ba-45f1-b74a-82ff518eeb10
var cFWPM_CONDITION_L2_FLAGS = windows.GUID{
	Data1: 0x7bc43cbf,
	Data2: 0x37ba,
	Data3: 0x45f1,
	Data4: [8]byte{0xb7, 0x4a, 0x82, 0xff, 0x51, 0x8e, 0xeb, 0x10},
}

type wtFwpmL2Flags uint32

const cFWP_CONDITION_L2_IS_VM2VM wtFwpmL2Flags = 0x00000010

var cFWPM_CONDITION_FLAGS = windows.GUID{
	Data1: 0x632ce23b,
	Data2: 0x5167,
	Data3: 0x435c,
	Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c},
}

type wtFwpmFlags uint32

const cFWP_CONDITION_FLAG_IS_LOOPBACK wtFwpmFlags = 0x00000001

// Defined in fwpmtypes.h
type wtFwpmFilterFlags uint32

const (
	cFWPM_FILTER_FLAG_NONE                                wtFwpmFilterFlags = 0x00000000
	cFWPM_FILTER_FLAG_PERSISTENT                          wtFwpmFilterFlags = 0x00000001
	cFWPM_FILTER_FLAG_BOOTTIME                            wtFwpmFilterFlags = 0x00000002
	cFWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT                wtFwpmFilterFlags = 0x00000004
	cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT                  wtFwpmFilterFlags = 0x00000008
	cFWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED      wtFwpmFilterFlags = 0x00000010
	cFWPM_FILTER_FLAG_DISABLED                            wtFwpmFilterFlags = 0x00000020
	cFWPM_FILTER_FLAG_INDEXED                             wtFwpmFilterFlags = 0x00000040
	cFWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT wtFwpmFilterFlags = 0x00000080
	cFWPM_FILTER_FLAG_SYSTEMOS_ONLY                       wtFwpmFilterFlags = 0x00000100
	cFWPM_FILTER_FLAG_GAMEOS_ONLY                         wtFwpmFilterFlags = 0x00000200
	cFWPM_FILTER_FLAG_SILENT_MODE                         wtFwpmFilterFlags = 0x00000400
	cFWPM_FILTER_FLAG_IPSEC_NO_ACQUIRE_INITIATE           wtFwpmFilterFlags = 0x00000800
)

// FWPM_LAYER_ALE_AUTH_CONNECT_V4 (c38d57d1-05a7-4c33-904f-7fbceee60e82) defined in fwpmu.h
var cFWPM_LAYER_ALE_AUTH_CONNECT_V4 = windows.GUID{
	Data1: 0xc38d57d1,
	Data2: 0x05a7,
	Data3: 0x4c33,
	Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
}

// e1cd9fe7-f4b5-4273-96c0-592e487b8650
var cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = windows.GUID{
	Data1: 0xe1cd9fe7,
	Data2: 0xf4b5,
	Data3: 0x4273,
	Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
}

// FWPM_LAYER_ALE_AUTH_CONNECT_V6 (4a72393b-319f-44bc-84c3-ba54dcb3b6b4) defined in fwpmu.h
var cFWPM_LAYER_ALE_AUTH_CONNECT_V6 = windows.GUID{
	Data1: 0x4a72393b,
	Data2: 0x319f,
	Data3: 0x44bc,
	Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
}

// a3b42c97-9f04-4672-b87e-cee9c483257f
var cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = windows.GUID{
	Data1: 0xa3b42c97,
	Data2: 0x9f04,
	Data3: 0x4672,
	Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
}

// 94c44912-9d6f-4ebf-b995-05ab8a088d1b
var cFWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE = windows.GUID{
	Data1: 0x94c44912,
	Data2: 0x9d6f,
	Data3: 0x4ebf,
	Data4: [8]byte{0xb9, 0x95, 0x05, 0xab, 0x8a, 0x08, 0x8d, 0x1b},
}

// d4220bd3-62ce-4f08-ae88-b56e8526df50
var cFWPM_LAYER_INBOUND_MAC_FRAME_NATIVE = windows.GUID{
	Data1: 0xd4220bd3,
	Data2: 0x62ce,
	Data3: 0x4f08,
	Data4: [8]byte{0xae, 0x88, 0xb5, 0x6e, 0x85, 0x26, 0xdf, 0x50},
}

// FWP_BITMAP_ARRAY64 defined in fwtypes.h
type wtFwpBitmapArray64 struct {
	bitmapArray64 [8]uint8 // Windows type: [8]UINT8
}

// FWP_BYTE_ARRAY6 defined in fwtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwp_byte_array6_)
type wtFwpByteArray6 struct {
	byteArray6 [6]uint8 // Windows type: [6]UINT8
}

// FWP_BYTE_ARRAY16 defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwp_byte_array16_)
type wtFwpByteArray16 struct {
	byteArray16 [16]uint8 // Windows type [16]UINT8
}

// FWP_CONDITION_VALUE0 defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwp_condition_value0).
type wtFwpConditionValue0 wtFwpValue0

// FWP_DATA_TYPE defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ne-fwptypes-fwp_data_type_)
type wtFwpDataType uint

const (
	cFWP_EMPTY                         wtFwpDataType = 0
	cFWP_UINT8                         wtFwpDataType = cFWP_EMPTY + 1
	cFWP_UINT16                        wtFwpDataType = cFWP_UINT8 + 1
	cFWP_UINT32                        wtFwpDataType = cFWP_UINT16 + 1
	cFWP_UINT64                        wtFwpDataType = cFWP_UINT32 + 1
	cFWP_INT8                          wtFwpDataType = cFWP_UINT64 + 1
	cFWP_INT16                         wtFwpDataType = cFWP_INT8 + 1
	cFWP_INT32                         wtFwpDataType = cFWP_INT16 + 1
	cFWP_INT64                         wtFwpDataType = cFWP_INT32 + 1
	cFWP_FLOAT                         wtFwpDataType = cFWP_INT64 + 1
	cFWP_DOUBLE                        wtFwpDataType = cFWP_FLOAT + 1
	cFWP_BYTE_ARRAY16_TYPE             wtFwpDataType = cFWP_DOUBLE + 1
	cFWP_BYTE_BLOB_TYPE                wtFwpDataType = cFWP_BYTE_ARRAY16_TYPE + 1
	cFWP_SID                           wtFwpDataType = cFWP_BYTE_BLOB_TYPE + 1
	cFWP_SECURITY_DESCRIPTOR_TYPE      wtFwpDataType = cFWP_SID + 1
	cFWP_TOKEN_INFORMATION_TYPE        wtFwpDataType = cFWP_SECURITY_DESCRIPTOR_TYPE + 1
	cFWP_TOKEN_ACCESS_INFORMATION_TYPE wtFwpDataType = cFWP_TOKEN_INFORMATION_TYPE + 1
	cFWP_UNICODE_STRING_TYPE           wtFwpDataType = cFWP_TOKEN_ACCESS_INFORMATION_TYPE + 1
	cFWP_BYTE_ARRAY6_TYPE              wtFwpDataType = cFWP_UNICODE_STRING_TYPE + 1
	cFWP_BITMAP_INDEX_TYPE             wtFwpDataType = cFWP_BYTE_ARRAY6_TYPE + 1
	cFWP_BITMAP_ARRAY64_TYPE           wtFwpDataType = cFWP_BITMAP_INDEX_TYPE + 1
	cFWP_SINGLE_DATA_TYPE_MAX          wtFwpDataType = 0xff
	cFWP_V4_ADDR_MASK                  wtFwpDataType = cFWP_SINGLE_DATA_TYPE_MAX + 1
	cFWP_V6_ADDR_MASK                  wtFwpDataType = cFWP_V4_ADDR_MASK + 1
	cFWP_RANGE_TYPE                    wtFwpDataType = cFWP_V6_ADDR_MASK + 1
	cFWP_DATA_TYPE_MAX                 wtFwpDataType = cFWP_RANGE_TYPE + 1
)

// FWP_V4_ADDR_AND_MASK defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwp_v4_addr_and_mask).
type wtFwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

// FWP_V6_ADDR_AND_MASK defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwp_v6_addr_and_mask).
type wtFwpV6AddrAndMask struct {
	addr         [16]uint8
	prefixLength uint8
}

// FWP_VALUE0 defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwp_value0_)
type wtFwpValue0 struct {
	_type wtFwpDataType
	value uintptr
}

// FWPM_DISPLAY_DATA0 defined in fwptypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwptypes/ns-fwptypes-fwpm_display_data0).
type wtFwpmDisplayData0 struct {
	name        *uint16 // Windows type: *wchar_t
	description *uint16 // Windows type: *wchar_t
}

// FWPM_FILTER_CONDITION0 defined in fwpmtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0).
type wtFwpmFilterCondition0 struct {
	fieldKey       windows.GUID // Windows type: GUID
	matchType      wtFwpMatchType
	conditionValue wtFwpConditionValue0
}

// FWPM_PROVIDER0 defined in fwpmtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0_)
type wtFwpProvider0 struct {
	providerKey  windows.GUID // Windows type: GUID
	displayData  wtFwpmDisplayData0
	flags        uint32
	providerData wtFwpByteBlob
	serviceName  *uint16 // Windows type: *wchar_t
}

type wtFwpmSessionFlagsValue uint32

const (
	cFWPM_SESSION_FLAG_DYNAMIC wtFwpmSessionFlagsValue = 0x00000001 // FWPM_SESSION_FLAG_DYNAMIC defined in fwpmtypes.h
)

// FWPM_SESSION0 defined in fwpmtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_session0).
type wtFwpmSession0 struct {
	sessionKey           windows.GUID // Windows type: GUID
	displayData          wtFwpmDisplayData0
	flags                wtFwpmSessionFlagsValue // Windows type UINT32
	txnWaitTimeoutInMSec uint32
	processId            uint32 // Windows type: DWORD
	sid                  *windows.SID
	username             *uint16 // Windows type: *wchar_t
	kernelMode           uint8   // Windows type: BOOL
}

type wtFwpmSublayerFlags uint32

const (
	cFWPM_SUBLAYER_FLAG_PERSISTENT wtFwpmSublayerFlags = 0x00000001 // FWPM_SUBLAYER_FLAG_PERSISTENT defined in fwpmtypes.h
)

// FWPM_SUBLAYER0 defined in fwpmtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0_)
type wtFwpmSublayer0 struct {
	subLayerKey  windows.GUID // Windows type: GUID
	displayData  wtFwpmDisplayData0
	flags        wtFwpmSublayerFlags
	providerKey  *windows.GUID // Windows type: *GUID
	providerData wtFwpByteBlob
	weight       uint16
}

// Defined in rpcdce.h
type wtRpcCAuthN uint32

const (
	cRPC_C_AUTHN_NONE    wtRpcCAuthN = 0
	cRPC_C_AUTHN_WINNT   wtRpcCAuthN = 10
	cRPC_C_AUTHN_DEFAULT wtRpcCAuthN = 0xFFFFFFFF
)

// FWPM_PROVIDER0 defined in fwpmtypes.h
// (https://docs.microsoft.com/sv-se/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0).
type wtFwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  wtFwpmDisplayData0
	flags        uint32
	providerData wtFwpByteBlob
	serviceName  *uint16
}

type wtIPProto uint32

const (
	cIPPROTO_ICMP   wtIPProto = 1
	cIPPROTO_ICMPV6 wtIPProto = 58
	cIPPROTO_TCP    wtIPProto = 6
	cIPPROTO_UDP    wtIPProto = 17
)

const (
	cFWP_ACTRL_MATCH_FILTER = 1
)

//go:build amd64 || arm64

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import "golang.org/x/sys/windows"

const (
	wtFwpByteBlob_Size        = 16
	wtFwpByteBlob_data_Offset = 8

	wtFwpConditionValue0_Size         = 16
	wtFwpConditionValue0_uint8_Offset = 8

	wtFwpmDisplayData0_Size               = 16
	wtFwpmDisplayData0_description_Offset = 8

	wtFwpmFilter0_Size                       = 200
	wtFwpmFilter0_displayData_Offset         = 16
	wtFwpmFilter0_flags_Offset               = 32
	wtFwpmFilter0_providerKey_Offset         = 40
	wtFwpmFilter0_providerData_Offset        = 48
	wtFwpmFilter0_layerKey_Offset            = 64
	wtFwpmFilter0_subLayerKey_Offset         = 80
	wtFwpmFilter0_weight_Offset              = 96
	wtFwpmFilter0_numFilterConditions_Offset = 112
	wtFwpmFilter0_filterCondition_Offset     = 120
	wtFwpmFilter0_action_Offset              = 128
	wtFwpmFilter0_providerContextKey_Offset  = 152
	wtFwpmFilter0_reserved_Offset            = 168
	wtFwpmFilter0_filterID_Offset            = 176
	wtFwpmFilter0_effectiveWeight_Offset     = 184

	wtFwpmFilterCondition0_Size                  = 40
	wtFwpmFilterCondition0_matchType_Offset      = 16
	wtFwpmFilterCondition0_conditionValue_Offset = 24

	wtFwpmSession0_Size                        = 72
	wtFwpmSession0_displayData_Offset          = 16
	wtFwpmSession0_flags_Offset                = 32
	wtFwpmSession0_txnWaitTimeoutInMSec_Offset = 36
	wtFwpmSession0_processId_Offset            = 40
	wtFwpmSession0_sid_Offset                  = 48
	wtFwpmSession0_username_Offset             = 56
	wtFwpmSession0_kernelMode_Offset           = 64

	wtFwpmSublayer0_Size                = 72
	wtFwpmSublayer0_displayData_Offset  = 16
	wtFwpmSublayer0_flags_Offset        = 32
	wtFwpmSublayer0_providerKey_Offset  = 40
	wtFwpmSublayer0_providerData_Offset = 48
	wtFwpmSublayer0_weight_Offset       = 64

	wtFwpProvider0_Size                = 64
	wtFwpProvider0_displayData_Offset  = 16
	wtFwpProvider0_flags_Offset        = 32
	wtFwpProvider0_providerData_Offset = 40
	wtFwpProvider0_serviceName_Offset  = 56

	wtFwpValue0_Size         = 16
	wtFwpValue0_value_Offset = 8
)

// FWPM_FILTER0 defined in fwpmtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
type wtFwpmFilter0 struct {
	filterKey           windows.GUID // Windows type: GUID
	displayData         wtFwpmDisplayData0
	flags               wtFwpmFilterFlags // Windows type: UINT32
	providerKey         *windows.GUID     // Windows type: *GUID
	providerData        wtFwpByteBlob
	layerKey            windows.GUID // Windows type: GUID
	subLayerKey         windows.GUID // Windows type: GUID
	weight              wtFwpValue0
	numFilterConditions uint32
	filterCondition     *wtFwpmFilterCondition0
	action              wtFwpmAction0
	offset1             [4]byte       // Layout correction field
	providerContextKey  windows.GUID  // Windows type: GUID
	reserved            *windows.GUID // Windows type: *GUID
	filterID            uint64
	effectiveWeight     wtFwpValue0
}

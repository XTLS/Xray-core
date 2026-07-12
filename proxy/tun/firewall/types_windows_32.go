//go:build 386 || arm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import "golang.org/x/sys/windows"

const (
	wtFwpByteBlob_Size        = 8
	wtFwpByteBlob_data_Offset = 4

	wtFwpConditionValue0_Size         = 8
	wtFwpConditionValue0_uint8_Offset = 4

	wtFwpmDisplayData0_Size               = 8
	wtFwpmDisplayData0_description_Offset = 4

	wtFwpmFilter0_Size                       = 152
	wtFwpmFilter0_displayData_Offset         = 16
	wtFwpmFilter0_flags_Offset               = 24
	wtFwpmFilter0_providerKey_Offset         = 28
	wtFwpmFilter0_providerData_Offset        = 32
	wtFwpmFilter0_layerKey_Offset            = 40
	wtFwpmFilter0_subLayerKey_Offset         = 56
	wtFwpmFilter0_weight_Offset              = 72
	wtFwpmFilter0_numFilterConditions_Offset = 80
	wtFwpmFilter0_filterCondition_Offset     = 84
	wtFwpmFilter0_action_Offset              = 88
	wtFwpmFilter0_providerContextKey_Offset  = 112
	wtFwpmFilter0_reserved_Offset            = 128
	wtFwpmFilter0_filterID_Offset            = 136
	wtFwpmFilter0_effectiveWeight_Offset     = 144

	wtFwpmFilterCondition0_Size                  = 28
	wtFwpmFilterCondition0_matchType_Offset      = 16
	wtFwpmFilterCondition0_conditionValue_Offset = 20

	wtFwpmSession0_Size                        = 48
	wtFwpmSession0_displayData_Offset          = 16
	wtFwpmSession0_flags_Offset                = 24
	wtFwpmSession0_txnWaitTimeoutInMSec_Offset = 28
	wtFwpmSession0_processId_Offset            = 32
	wtFwpmSession0_sid_Offset                  = 36
	wtFwpmSession0_username_Offset             = 40
	wtFwpmSession0_kernelMode_Offset           = 44

	wtFwpmSublayer0_Size                = 44
	wtFwpmSublayer0_displayData_Offset  = 16
	wtFwpmSublayer0_flags_Offset        = 24
	wtFwpmSublayer0_providerKey_Offset  = 28
	wtFwpmSublayer0_providerData_Offset = 32
	wtFwpmSublayer0_weight_Offset       = 40

	wtFwpProvider0_Size                = 40
	wtFwpProvider0_displayData_Offset  = 16
	wtFwpProvider0_flags_Offset        = 24
	wtFwpProvider0_providerData_Offset = 28
	wtFwpProvider0_serviceName_Offset  = 36

	wtFwpTokenInformation_Size = 16

	wtFwpValue0_Size         = 8
	wtFwpValue0_value_Offset = 4
)

// FWPM_FILTER0 defined in fwpmtypes.h
// (https://docs.microsoft.com/en-us/windows/desktop/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
type wtFwpmFilter0 struct {
	filterKey           windows.GUID // Windows type: GUID
	displayData         wtFwpmDisplayData0
	flags               wtFwpmFilterFlags
	providerKey         *windows.GUID // Windows type: *GUID
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
	offset2             [4]byte       // Layout correction field
	filterID            uint64
	effectiveWeight     wtFwpValue0
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmengineopen0
//sys	fwpmEngineOpen0(serverName *uint16, authnService wtRpcCAuthN, authIdentity *uintptr, session *wtFwpmSession0, engineHandle unsafe.Pointer) (err error) [failretval!=0] = fwpuclnt.FwpmEngineOpen0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmengineclose0
//sys	fwpmEngineClose0(engineHandle uintptr) (err error) [failretval!=0] = fwpuclnt.FwpmEngineClose0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmsublayeradd0
//sys	fwpmSubLayerAdd0(engineHandle uintptr, subLayer *wtFwpmSublayer0, sd uintptr) (err error) [failretval!=0] = fwpuclnt.FwpmSubLayerAdd0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
//sys	fwpmGetAppIdFromFileName0(fileName *uint16, appID unsafe.Pointer) (err error) [failretval!=0] = fwpuclnt.FwpmGetAppIdFromFileName0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmfreememory0
//sys	fwpmFreeMemory0(p unsafe.Pointer) = fwpuclnt.FwpmFreeMemory0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmfilteradd0
//sys	fwpmFilterAdd0(engineHandle uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) (err error) [failretval!=0] = fwpuclnt.FwpmFilterAdd0

// https://docs.microsoft.com/en-us/windows/desktop/api/Fwpmu/nf-fwpmu-fwpmtransactionbegin0
//sys	fwpmTransactionBegin0(engineHandle uintptr, flags uint32) (err error) [failretval!=0] = fwpuclnt.FwpmTransactionBegin0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
//sys	fwpmTransactionCommit0(engineHandle uintptr) (err error) [failretval!=0] = fwpuclnt.FwpmTransactionCommit0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmtransactionabort0
//sys	fwpmTransactionAbort0(engineHandle uintptr) (err error) [failretval!=0] = fwpuclnt.FwpmTransactionAbort0

// https://docs.microsoft.com/en-us/windows/desktop/api/fwpmu/nf-fwpmu-fwpmprovideradd0
//sys	fwpmProviderAdd0(engineHandle uintptr, provider *wtFwpmProvider0, sd uintptr) (err error) [failretval!=0] = fwpuclnt.FwpmProviderAdd0

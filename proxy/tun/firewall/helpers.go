/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func runTransaction(session uintptr, operation wfpObjectInstaller) error {
	err := fwpmTransactionBegin0(session, 0)
	if err != nil {
		return wrapErr(err)
	}

	err = operation(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	err = fwpmTransactionCommit0(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	return nil
}

func createWtFwpmDisplayData0(name, description string) (*wtFwpmDisplayData0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, wrapErr(err)
	}

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, wrapErr(err)
	}

	return &wtFwpmDisplayData0{
		name:        namePtr,
		description: descriptionPtr,
	}, nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}

func wrapErr(err error) error {
	if _, ok := err.(syscall.Errno); !ok {
		return err
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("Firewall error at unknown location: %w", err)
	}
	return fmt.Errorf("Firewall error at %s:%d: %w", file, line, err)
}

func getCurrentProcessSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return nil, wrapErr(err)
	}
	defer processToken.Close()
	gs, err := processToken.GetTokenGroups()
	if err != nil {
		return nil, wrapErr(err)
	}
	var sid *windows.SID
	for _, g := range gs.AllGroups() {
		if g.Attributes != windows.SE_GROUP_ENABLED|windows.SE_GROUP_ENABLED_BY_DEFAULT|windows.SE_GROUP_OWNER {
			continue
		}
		// We could be checking != 6, but hopefully Microsoft will update
		// RtlCreateServiceSid to use SHA2, which will then likely bump
		// this up. So instead just roll with a minimum.
		if !g.Sid.IsValid() || g.Sid.IdentifierAuthority() != windows.SECURITY_NT_AUTHORITY || g.Sid.SubAuthorityCount() < 6 || g.Sid.SubAuthority(0) != 80 {
			continue
		}
		sid = g.Sid
		break
	}
	if sid == nil {
		return nil, wrapErr(windows.ERROR_NO_SUCH_GROUP)
	}

	access := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: cFWP_ACTRL_MATCH_FILTER,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	dacl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		return nil, wrapErr(err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, wrapErr(err)
	}
	err = sd.SetDACL(dacl, true, false)
	if err != nil {
		return nil, wrapErr(err)
	}
	sd, err = sd.ToSelfRelative()
	if err != nil {
		return nil, wrapErr(err)
	}
	return sd, nil
}

func getCurrentProcessAppID() (*wtFwpByteBlob, error) {
	currentFile, err := os.Executable()
	if err != nil {
		return nil, wrapErr(err)
	}

	curFilePtr, err := windows.UTF16PtrFromString(currentFile)
	if err != nil {
		return nil, wrapErr(err)
	}

	var appID *wtFwpByteBlob
	err = fwpmGetAppIdFromFileName0(curFilePtr, unsafe.Pointer(&appID))
	if err != nil {
		return nil, wrapErr(err)
	}
	return appID, nil
}

package rawpacket

import (
	"log"
	"os/exec"
	"strconv"
)

// suppressKernelRST installs an iptables rule that drops the kernel's
// RST replies for the relay listen port (the fake TCP handshake has no
// kernel socket behind it, so the kernel would answer our own SYN with
// RST). Only RSTs matching the relay port are dropped; the raw socket's
// spoofed packets are unaffected. Returns true when the rule was
// installed.
func suppressKernelRST(port uint16) bool {
	if port == 0 {
		return false
	}
	rule := []string{"-I", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", strconv.Itoa(int(port)), "-j", "DROP"}
	err := exec.Command("iptables", rule...).Run()
	if err != nil {
		log.Printf("[rawpacket] failed to suppress kernel RST on port %d: %v", port, err)
		return false
	}
	log.Printf("[rawpacket] suppressed kernel RST on port %d", port)
	return true
}

// restoreKernelRST removes the rule installed by suppressKernelRST.
// managed must be the value returned by suppressKernelRST.
func restoreKernelRST(port uint16, managed bool) {
	if !managed || port == 0 {
		return
	}
	rule := []string{"-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", strconv.Itoa(int(port)), "-j", "DROP"}
	err := exec.Command("iptables", rule...).Run()
	if err != nil {
		log.Printf("[rawpacket] failed to restore kernel RST on port %d: %v", port, err)
		return
	}
	log.Printf("[rawpacket] restored kernel RST on port %d", port)
}

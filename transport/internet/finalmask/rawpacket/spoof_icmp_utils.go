package rawpacket

import (
	"log"
	"os/exec"
	"runtime"
)

func suppressICMPEchoReply() bool {
	switch runtime.GOOS {
	case "linux":
		err := exec.Command("sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1").Run()
		if err != nil {
			log.Printf("[rawpacket] failed to suppress ICMP echo replies: %v", err)
			return false
		}
		log.Printf("[rawpacket] suppressed kernel ICMP echo replies")
		return true
	case "freebsd", "openbsd":
		err := exec.Command("sysctl", "net.inet.icmp.bmcastecho=0").Run()
		if err != nil {
			log.Printf("[rawpacket] failed to suppress ICMP echo replies on %s: %v", runtime.GOOS, err)
			return false
		}
		log.Printf("[rawpacket] suppressed kernel ICMP echo replies on %s", runtime.GOOS)
		return true
	default:
		log.Printf("[rawpacket] ICMP echo reply suppression not supported on %s", runtime.GOOS)
		return false
	}
}

func restoreICMPEchoReply() {
	switch runtime.GOOS {
	case "linux":
		err := exec.Command("sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=0").Run()
		if err != nil {
			log.Printf("[rawpacket] failed to restore ICMP echo replies: %v", err)
			return
		}
		log.Printf("[rawpacket] restored kernel ICMP echo replies")
	case "freebsd", "openbsd":
		err := exec.Command("sysctl", "net.inet.icmp.bmcastecho=1").Run()
		if err != nil {
			log.Printf("[rawpacket] failed to restore ICMP echo replies on %s: %v", runtime.GOOS, err)
		}
	}
}

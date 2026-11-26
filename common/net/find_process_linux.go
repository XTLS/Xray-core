//go:build linux && !android

package net

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (PID int, Name string, AbsolutePath string, err error) {
	return FindProcessMatching(network, srcIP, srcPort, destIP, destPort, nil)
}

// FindProcessMatching is FindProcess for a caller that needs only the processes that accept returns true for.
//
// Linux has no table from a socket to its process. The owner of the socket is found by a readlink of
// /proc/<pid>/fd/* of each process, so a lookup costs about one readlink for each fd open on the system.
// With accept, it is called for each process in /proc, not only for the owner, and the fds of a process
// are read only if accept returns true for its PID, name and executable path. That costs one readlink of
// /proc/<pid>/exe for each process. If no accepted process owns the socket, the error is ErrProcessNotMatched.
func FindProcessMatching(network, srcIP string, srcPort uint16, destIP string, destPort uint16, accept func(pid int, name, absPath string) bool) (PID int, Name string, AbsolutePath string, err error) {
	isLocal, err := IsLocal(net.ParseIP(srcIP))
	if err != nil {
		return 0, "", "", errors.New("failed to determine if address is local: ", err)
	}
	if !isLocal {
		return 0, "", "", ErrNotLocal
	}
	if network != "tcp" && network != "udp" {
		panic("Unsupported network type for process lookup.")
	}

	var procFiles []string

	switch network {
	case "tcp":
		if net.ParseIP(srcIP).To4() != nil {
			procFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}
		} else {
			procFiles = []string{"/proc/net/tcp6"}
		}
	case "udp":
		if net.ParseIP(srcIP).To4() != nil {
			procFiles = []string{"/proc/net/udp", "/proc/net/udp6"}
		} else {
			procFiles = []string{"/proc/net/udp6", "/proc/net/udp"}
		}
	default:
		panic("Unsupported network type for process lookup.")
	}

	targetHexAddrs := []string{formatProcNetAddress(net.ParseIP(srcIP).To16(), Port(srcPort))}
	if ipv4 := net.ParseIP(srcIP).To4(); ipv4 != nil {
		// the one above is then the IPv4-mapped IPv6 address that an IPv6 socket has it as, in the IPv6 file
		targetHexAddrs = append(targetHexAddrs, formatProcNetAddress(ipv4, Port(srcPort)))
	}

	portFallback := ""
	if network == "udp" {
		portFallback = fmt.Sprintf(":%04X", srcPort)
	}

	inode, err := findInodeInFiles(procFiles, targetHexAddrs, portFallback)
	if err != nil {
		return 0, "", "", errors.New("could not search in ", strings.Join(procFiles, " and ")).Base(err)
	}
	if inode == "" {
		return 0, "", "", errors.New("connection for ", srcIP, ":", srcPort, " not found in ", strings.Join(procFiles, " or "))
	}

	pidStr, absPath, err := findPidByInode(inode, accept)
	if err != nil {
		return 0, "", "", errors.New("could not find PID for inode ", inode, ": ", err)
	}
	if pidStr == "" {
		if accept != nil {
			return 0, "", "", ErrProcessNotMatched
		}
		return 0, "", "", errors.New("no process found for inode ", inode)
	}

	if absPath == "" {
		absPath, err = getAbsPath(pidStr)
		if err != nil {
			return 0, "", "", errors.New("could not get process name for PID ", pidStr, ":", err)
		}
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, "", "", errors.New("failed to parse PID: ", err)
	}

	return pid, procNameOf(absPath), absPath, nil
}

func procNameOf(absPath string) string {
	return absPath[strings.LastIndexByte(absPath, '/')+1:]
}

// formatProcNetAddress formats the 4 or 16 bytes of addr as they are: an IPv4-mapped IPv6 address stays one
func formatProcNetAddress(addr net.IP, port Port) string {
	ipBytes := []byte(addr)

	var formatted strings.Builder
	formatted.Grow(len(ipBytes)*2 + 5)
	for i := 0; i < len(ipBytes); i += 4 {
		fmt.Fprintf(&formatted, "%08X", binary.NativeEndian.Uint32(ipBytes[i:i+4]))
	}
	fmt.Fprintf(&formatted, ":%04X", uint16(port))
	return formatted.String()
}

func findInodeInFiles(filePaths []string, targetHexAddrs []string, portFallback string) (string, error) {
	onlyMatchedPort := ""

	for i, filePath := range filePaths {
		file, err := os.Open(filePath)
		if err != nil {
			if i > 0 && os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}

			// a socket without a process, as in TIME_WAIT, has inode 0, and can have the same local address as a new socket
			if fields[9] == "0" {
				continue
			}

			localAddress := fields[1]
			if slices.Contains(targetHexAddrs, localAddress) {
				return fields[9], nil
			}
			if portFallback != "" && strings.HasSuffix(localAddress, portFallback) {
				wildcardIP := strings.TrimSuffix(localAddress, portFallback)
				if (len(wildcardIP) == 8 || len(wildcardIP) == 32) && strings.Trim(wildcardIP, "0") == "" {
					onlyMatchedPort = fields[9]
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return "", err
		}
	}

	return onlyMatchedPort, nil
}

// findPidByInode returns the PID of the process that owns the socket, or "" if there is none.
// With accept, it searches only the processes that accept returns true for, and returns the
// executable path too.
func findPidByInode(inode string, accept func(pid int, name, absPath string) bool) (string, string, error) {
	procDir, err := os.ReadDir("/proc")
	if err != nil {
		return "", "", err
	}

	targetLink := "socket:[" + inode + "]"

	for _, entry := range procDir {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		pidNum, err := strconv.Atoi(pid)
		if err != nil {
			continue
		}

		absPath := ""
		if accept != nil {
			// the exe link can't be read for kernel threads, and for the processes of other users
			// without root, but then their fds can't be read either
			absPath, err = getAbsPath(pid)
			if err != nil || !accept(pidNum, procNameOf(absPath), absPath) {
				continue
			}
		}

		fdPath := fmt.Sprintf("/proc/%s/fd", pid)
		fdDir, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdDir {
			linkPath := fmt.Sprintf("%s/%s", fdPath, fdEntry.Name())
			linkTarget, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			if linkTarget == targetLink {
				return pid, absPath, nil
			}
		}
	}
	return "", "", nil
}

func getAbsPath(pid string) (string, error) {
	path := fmt.Sprintf("/proc/%s/exe", pid)
	return os.Readlink(path)
}

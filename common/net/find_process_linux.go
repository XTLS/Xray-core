//go:build linux && !android

package net

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (PID int, Name string, AbsolutePath string, err error) {
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

	var procFile string

	switch network {
	case "tcp":
		if net.ParseIP(srcIP).To4() != nil {
			procFile = "/proc/net/tcp"
		} else {
			procFile = "/proc/net/tcp6"
		}
	case "udp":
		if net.ParseIP(srcIP).To4() != nil {
			procFile = "/proc/net/udp"
		} else {
			procFile = "/proc/net/udp6"
		}
	default:
		panic("Unsupported network type for process lookup.")
	}

	targetHexAddr := formatProcNetAddress(net.ParseIP(srcIP), Port(srcPort))

	inode, err := findInodeInFile(procFile, targetHexAddr)
	if err != nil {
		return 0, "", "", errors.New("could not search in ", procFile).Base(err)
	}
	if inode == "" {
		return 0, "", "", errors.New("connection for ", srcIP, ":", srcPort, " not found in ", procFile)
	}

	pidStr, err := findPidByInode(inode)
	if err != nil {
		return 0, "", "", errors.New("could not find PID for inode ", inode, ": ", err)
	}
	if pidStr == "" {
		return 0, "", "", errors.New("no process found for inode ", inode)
	}

	absPath, err := getAbsPath(pidStr)
	if err != nil {
		return 0, "", "", errors.New("could not get process name for PID ", pidStr, ":", err)
	}

	nameSplit := strings.Split(absPath, "/")
	procName := nameSplit[len(nameSplit)-1]

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, "", "", errors.New("failed to parse PID: ", err)
	}

	return pid, procName, absPath, nil
}

func formatProcNetAddress(addr net.IP, port Port) string {
	var ipBytes []byte
	if ipv4 := addr.To4(); ipv4 != nil {
		ipBytes = ipv4
	} else {
		ipBytes = addr.To16()
	}

	var formatted strings.Builder
	formatted.Grow(len(ipBytes)*2 + 5)
	for i := 0; i < len(ipBytes); i += 4 {
		fmt.Fprintf(&formatted, "%08X", binary.NativeEndian.Uint32(ipBytes[i:i+4]))
	}
	fmt.Fprintf(&formatted, ":%04X", uint16(port))
	return formatted.String()
}

func findInodeInFile(filePath, targetHexAddr string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 10 {
			continue
		}

		localAddress := fields[1]
		if localAddress == targetHexAddr {
			inode := fields[9]
			return inode, nil
		}
	}

	return "", scanner.Err()
}

func findPidByInode(inode string) (string, error) {
	procDir, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	targetLink := "socket:[" + inode + "]"

	for _, entry := range procDir {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
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
				return pid, nil
			}
		}
	}
	return "", nil
}

func getAbsPath(pid string) (string, error) {
	path := fmt.Sprintf("/proc/%s/exe", pid)
	return os.Readlink(path)
}

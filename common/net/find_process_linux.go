//go:build linux && !android

package net

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
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

	targetHexAddr, err := formatLittleEndianString(net.ParseIP(srcIP), Port(srcPort))
	if err != nil {
		return 0, "", "", errors.New("failed to format address: ", err)
	}

	matches, err := findSocketMatchesInFile(procFile, targetHexAddr, network == "udp")
	if err != nil {
		return 0, "", "", errors.New("could not search in ", procFile).Base(err)
	}
	inodes := matchingSocketInodes(matches, nil, nil)
	knownPIDs := make(map[string]string)
	if len(matches.exact) == 0 && network == "udp" && net.ParseIP(srcIP).To4() != nil {
		const ipv6ProcFile = "/proc/net/udp6"
		mappedAddr, err := formatIPv6LittleEndianString(net.ParseIP(srcIP).To16(), Port(srcPort))
		if err != nil {
			return 0, "", "", errors.New("failed to format mapped IPv6 address: ", err)
		}
		mappedExact, ipv6Wildcard, err := findIPv4CompatibleInodes(ipv6ProcFile, mappedAddr, Port(srcPort))
		if err != nil && !os.IsNotExist(err) {
			return 0, "", "", errors.New("could not search in ", ipv6ProcFile).Base(err)
		}
		if len(mappedExact) > 0 {
			inodes = matchingSocketInodes(socketMatches{}, mappedExact, nil)
		} else {
			var err error
			inodes, knownPIDs, err = findIPv4WildcardCandidates(matches.wildcard, ipv6Wildcard, ipv6SocketModeForInode)
			if err != nil {
				return 0, "", "", err
			}
		}
	}
	if len(inodes) == 0 {
		return 0, "", "", errors.New("connection for ", srcIP, ":", srcPort, " not found in ", procFile)
	}

	knownPID, err := findUniqueProcess(inodes, func(inode string) (string, error) {
		if pid := knownPIDs[inode]; pid != "" {
			return pid, nil
		}
		return findPidByInode(inode)
	})
	if err != nil {
		return 0, "", "", err
	}

	absPath, err := getAbsPath(knownPID)
	if err != nil {
		return 0, "", "", errors.New("could not get process name for PID ", knownPID, ":", err)
	}

	nameSplit := strings.Split(absPath, "/")
	procName := nameSplit[len(nameSplit)-1]

	pid, err := strconv.Atoi(knownPID)
	if err != nil {
		return 0, "", "", errors.New("failed to parse PID: ", err)
	}

	return pid, procName, absPath, nil
}

func formatLittleEndianString(addr net.IP, port Port) (string, error) {
	ip := addr
	if ip.To4() != nil {
		ipBytes := append([]byte(nil), ip.To4()...)
		for i, j := 0, len(ipBytes)-1; i < j; i, j = i+1, j-1 {
			ipBytes[i], ipBytes[j] = ipBytes[j], ipBytes[i]
		}
		return formatProcAddress(ipBytes, port), nil
	}
	return formatIPv6LittleEndianString(ip, port)
}

func formatIPv6LittleEndianString(addr net.IP, port Port) (string, error) {
	ipBytes := append([]byte(nil), addr.To16()...)
	if ipBytes == nil {
		return "", errors.New("invalid IPv6 format for ", addr)
	}
	for offset := 0; offset < len(ipBytes); offset += 4 {
		for i, j := offset, offset+3; i < j; i, j = i+1, j-1 {
			ipBytes[i], ipBytes[j] = ipBytes[j], ipBytes[i]
		}
	}
	return formatProcAddress(ipBytes, port), nil
}

func formatProcAddress(ipBytes []byte, port Port) string {
	portHex := fmt.Sprintf("%04X", uint16(port))
	ipHex := strings.ToUpper(hex.EncodeToString(ipBytes))
	return fmt.Sprintf("%s:%s", ipHex, portHex)
}

type socketMatches struct {
	exact    []string
	wildcard []string
}

func matchingSocketInodes(matches socketMatches, mappedExact, dualStackWildcard []string) []string {
	exact := append(append([]string(nil), matches.exact...), mappedExact...)
	if len(exact) > 0 {
		return uniqueStrings(exact)
	}
	return uniqueStrings(append(append([]string(nil), matches.wildcard...), dualStackWildcard...))
}

func uniqueStrings(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	return mapKeys(unique)
}

func findSocketMatchesInFile(filePath, targetHexAddr string, allowWildcard bool) (socketMatches, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return socketMatches{}, err
	}
	defer file.Close()

	targetSeparator := strings.LastIndexByte(targetHexAddr, ':')
	if targetSeparator < 0 {
		return socketMatches{}, errors.New("invalid target address ", targetHexAddr)
	}
	targetPort := targetHexAddr[targetSeparator+1:]
	targetAddressBytes := []byte(targetHexAddr)
	targetPortBytes := []byte(targetPort)
	exactInodes := make(map[string]struct{})
	wildcardInodes := make(map[string]struct{})

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		localAddress, inode, ok := procNetSocketFields(scanner.Bytes())
		if !ok {
			continue
		}

		if bytes.Equal(localAddress, targetAddressBytes) {
			exactInodes[string(inode)] = struct{}{}
			continue
		}
		if allowWildcard {
			separator := bytes.LastIndexByte(localAddress, ':')
			if separator < 0 || !bytes.EqualFold(localAddress[separator+1:], targetPortBytes) {
				continue
			}
			if allZeroBytes(localAddress[:separator]) {
				wildcardInodes[string(inode)] = struct{}{}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return socketMatches{}, err
	}
	return socketMatches{
		exact:    mapKeys(exactInodes),
		wildcard: mapKeys(wildcardInodes),
	}, nil
}

func findIPv4CompatibleInodes(filePath, mappedTarget string, port Port) (mappedExact, wildcard []string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	targetSeparator := strings.LastIndexByte(mappedTarget, ':')
	if targetSeparator < 0 {
		return nil, nil, errors.New("invalid target address ", mappedTarget)
	}
	targetPort := mappedTarget[targetSeparator+1:]
	targetPortBytes := []byte(targetPort)
	wildcardAddress, err := formatIPv6LittleEndianString(net.IPv6zero, port)
	if err != nil {
		return nil, nil, err
	}
	wildcardSeparator := strings.LastIndexByte(wildcardAddress, ':')
	wildcardIP := wildcardAddress[:wildcardSeparator]
	wildcardIPBytes := []byte(wildcardIP)
	mappedTargetBytes := []byte(mappedTarget)
	exactInodes := make(map[string]struct{})
	wildcardInodes := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		localAddress, inode, ok := procNetSocketFields(scanner.Bytes())
		if !ok {
			continue
		}
		if bytes.Equal(localAddress, mappedTargetBytes) {
			exactInodes[string(inode)] = struct{}{}
			continue
		}
		separator := bytes.LastIndexByte(localAddress, ':')
		if separator >= 0 &&
			bytes.EqualFold(localAddress[separator+1:], targetPortBytes) &&
			bytes.EqualFold(localAddress[:separator], wildcardIPBytes) {
			wildcardInodes[string(inode)] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return mapKeys(exactInodes), mapKeys(wildcardInodes), nil
}

func procNetSocketFields(line []byte) (localAddress, inode []byte, ok bool) {
	fieldIndex := 0
	for offset := 0; offset < len(line); {
		for offset < len(line) && (line[offset] == ' ' || line[offset] == '\t') {
			offset++
		}
		if offset == len(line) {
			break
		}
		start := offset
		for offset < len(line) && line[offset] != ' ' && line[offset] != '\t' {
			offset++
		}
		switch fieldIndex {
		case 1:
			localAddress = line[start:offset]
		case 9:
			inode = line[start:offset]
			return localAddress, inode, len(localAddress) > 0
		}
		fieldIndex++
	}
	return nil, nil, false
}

func allZeroBytes(value []byte) bool {
	for _, b := range value {
		if b != '0' {
			return false
		}
	}
	return len(value) > 0
}

func findUniqueProcess(inodes []string, lookupPID func(string) (string, error)) (string, error) {
	pids := make(map[string]struct{})
	for _, inode := range inodes {
		pid, err := lookupPID(inode)
		if err != nil {
			return "", errors.New("could not find PID for inode ", inode, ": ", err)
		}
		if pid == "" {
			return "", errors.New("no process found for inode ", inode)
		}
		pids[pid] = struct{}{}
	}
	if len(pids) > 1 {
		return "", errors.New("ambiguous process lookup: ", len(pids), " processes own matching sockets")
	}
	for pid := range pids {
		return pid, nil
	}
	return "", nil
}

type ipv6SocketMode uint8

const (
	ipv6SocketUnknown ipv6SocketMode = iota
	ipv6SocketOnly
	ipv6DualStack
)

func findIPv4WildcardCandidates(ipv4Wildcard, ipv6Wildcard []string, socketMode func(string) (ipv6SocketMode, error)) ([]string, map[string]string, error) {
	dualStack := make([]string, 0, len(ipv6Wildcard))
	unknown := 0
	for _, inode := range ipv6Wildcard {
		mode, err := socketMode(inode)
		if err != nil {
			return nil, nil, err
		}
		switch mode {
		case ipv6DualStack:
			dualStack = append(dualStack, inode)
		case ipv6SocketUnknown:
			unknown++
		}
	}
	if unknown > 0 && len(ipv4Wildcard)+len(dualStack) > 0 {
		return nil, nil, errors.New("ambiguous process lookup: ", unknown, " IPv6 socket(s) have unknown IPV6_V6ONLY state alongside other IPv4 candidates")
	}

	knownPIDs := make(map[string]string, len(dualStack))
	currentPID := strconv.Itoa(os.Getpid())
	for _, inode := range dualStack {
		knownPIDs[inode] = currentPID
	}
	return matchingSocketInodes(socketMatches{wildcard: ipv4Wildcard}, nil, dualStack), knownPIDs, nil
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func ipv6SocketModeForInode(inode string) (ipv6SocketMode, error) {
	// /proc/net/udp6 does not report IPV6_V6ONLY, so only verify descriptors owned here.
	fdEntries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ipv6SocketUnknown, errors.New("could not inspect current process sockets").Base(err)
	}

	for _, entry := range fdEntries {
		fdPath := "/proc/self/fd/" + entry.Name()
		target, err := os.Readlink(fdPath)
		if err != nil || target != "socket:["+inode+"]" {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		duplicateFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(duplicateFD, &stat)
		if statErr != nil || strconv.FormatUint(stat.Ino, 10) != inode {
			_ = unix.Close(duplicateFD)
			continue
		}
		v6Only, sockoptErr := unix.GetsockoptInt(duplicateFD, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		_ = unix.Close(duplicateFD)
		if sockoptErr != nil {
			return ipv6SocketModeFromResult(0, sockoptErr), nil
		}
		return ipv6SocketModeFromResult(v6Only, nil), nil
	}

	return ipv6SocketUnknown, nil
}

func ipv6SocketModeFromResult(v6Only int, err error) ipv6SocketMode {
	if err != nil {
		return ipv6SocketUnknown
	}
	if v6Only == 0 {
		return ipv6DualStack
	}
	return ipv6SocketOnly
}

func findPidByInode(inode string) (string, error) {
	targetLink := "socket:[" + inode + "]"
	selfFDPath := "/proc/self/fd"
	selfFDDir, err := os.ReadDir(selfFDPath)
	if err != nil {
		return "", errors.New("could not inspect current process descriptors in ", selfFDPath).Base(err)
	}
	for _, fdEntry := range selfFDDir {
		linkPath := fmt.Sprintf("%s/%s", selfFDPath, fdEntry.Name())
		linkTarget, err := os.Readlink(linkPath)
		if err != nil {
			if os.IsPermission(err) {
				return "", errors.New("permission denied while checking socket owner ", linkPath).Base(err)
			}
			continue
		}
		if linkTarget == targetLink {
			return strconv.Itoa(os.Getpid()), nil
		}
	}

	procDir, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	permissionDenied := false
	for _, entry := range procDir {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		if pid == strconv.Itoa(os.Getpid()) {
			continue
		}

		fdPath := fmt.Sprintf("/proc/%s/fd", pid)
		fdDir, err := os.ReadDir(fdPath)
		if err != nil {
			if os.IsPermission(err) {
				permissionDenied = true
			}
			continue
		}

		for _, fdEntry := range fdDir {
			linkPath := fmt.Sprintf("%s/%s", fdPath, fdEntry.Name())
			linkTarget, err := os.Readlink(linkPath)
			if err != nil {
				if os.IsPermission(err) {
					permissionDenied = true
				}
				continue
			}
			if linkTarget == targetLink {
				return pid, nil
			}
		}
	}
	if permissionDenied {
		return "", errors.New("could not find socket inode ", inode, " because some process descriptors are not accessible")
	}
	return "", nil
}

func getAbsPath(pid string) (string, error) {
	path := fmt.Sprintf("/proc/%s/exe", pid)
	return os.Readlink(path)
}

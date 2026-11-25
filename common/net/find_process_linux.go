//go:build linux && !android

package net

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

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

	socket, err := findSocketInode(network, net.ParseIP(srcIP), srcPort)
	if err != nil {
		return 0, "", "", errors.New("could not query sockets using netlink").Base(err)
	}
	if socket == nil {
		return 0, "", "", errors.New("connection for ", srcIP, ":", srcPort, " not found")
	}

	pidStr, err := findPidByInode(socket.inode, socket.uid)
	if err != nil {
		return 0, "", "", errors.New("could not find PID for inode ", socket.inode, ": ", err)
	}
	if pidStr == "" {
		return 0, "", "", errors.New("no process found for inode ", socket.inode)
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

type processSocket struct {
	inode string
	uid   uint32
}

// Layouts are defined by Linux's inet_diag_req_v2 and inet_diag_msg.
const (
	inetDiagRequestSize  = 56
	inetDiagResponseSize = 72
	tcpBoundInactive     = 13
)

func findSocketInode(network string, ip net.IP, port uint16) (*processSocket, error) {
	families := []uint8{unix.AF_INET6}
	if ip.To4() != nil {
		families = []uint8{unix.AF_INET, unix.AF_INET6}
	} else if network == "udp" {
		families = append(families, unix.AF_INET)
	}

	protocol := byte(unix.IPPROTO_UDP)
	if network == "tcp" {
		protocol = unix.IPPROTO_TCP
	}

	var wildcard *processSocket
	for _, family := range families {
		request := make([]byte, inetDiagRequestSize)
		request[0], request[1] = family, protocol
		states := ^uint32(0)
		if network == "tcp" {
			states &^= 1 << tcpBoundInactive
		}
		binary.NativeEndian.PutUint32(request[4:8], states)
		binary.BigEndian.PutUint16(request[8:10], port)
		if family == unix.AF_INET {
			copy(request[12:28], ip.To4())
		} else {
			copy(request[12:28], ip.To16())
		}
		binary.NativeEndian.PutUint32(request[48:52], ^uint32(0))
		binary.NativeEndian.PutUint32(request[52:56], ^uint32(0))

		req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
		req.AddRawData(request)
		var exact *processSocket
		var parseErr error
		err := req.ExecuteIter(unix.NETLINK_INET_DIAG, nl.SOCK_DIAG_BY_FAMILY, func(msg []byte) bool {
			if len(msg) < inetDiagResponseSize {
				parseErr = fmt.Errorf("short inet_diag response: %d bytes", len(msg))
				return false
			}
			if msg[0] != family || binary.BigEndian.Uint16(msg[4:6]) != port {
				return true
			}
			source := net.IP(msg[8:24])
			if family == unix.AF_INET {
				source = source[:4]
			}
			if !source.Equal(ip) && !(network == "udp" && source.IsUnspecified()) {
				return true
			}
			socket := &processSocket{
				uid:   binary.NativeEndian.Uint32(msg[64:68]),
				inode: strconv.FormatUint(uint64(binary.NativeEndian.Uint32(msg[68:72])), 10),
			}
			if source.Equal(ip) {
				exact = socket
				return false
			}
			wildcard = socket
			return true
		})
		if err != nil {
			return nil, err
		}
		if parseErr != nil {
			return nil, parseErr
		}
		if exact != nil {
			return exact, nil
		}
	}
	return wildcard, nil
}

func findPidByInode(inode string, uid uint32) (string, error) {
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

		info, err := entry.Info()
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return "", fmt.Errorf("unexpected stat data for process %s", pid)
		}
		if stat.Uid != uid {
			continue
		}
		if processHasSocket(pid, targetLink) {
			return pid, nil
		}
	}
	return "", nil
}

func processHasSocket(pid, targetLink string) bool {
	fdPath := filepath.Join("/proc", pid, "fd")
	fdDir, err := os.ReadDir(fdPath)
	if err != nil {
		return false
	}

	buffer := make([]byte, unix.PathMax)
	for _, fdEntry := range fdDir {
		n, err := unix.Readlink(filepath.Join(fdPath, fdEntry.Name()), buffer)
		if err != nil {
			continue
		}
		if string(buffer[:n]) == targetLink {
			return true
		}
	}
	return false
}

func getAbsPath(pid string) (string, error) {
	path := fmt.Sprintf("/proc/%s/exe", pid)
	return os.Readlink(path)
}

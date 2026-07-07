package internet

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
)

const (
	// TCP_FASTOPEN 是 Windows 平台 TCP Fast Open 的套接字选项常量值。
	// 该功能允许在 SYN 握手阶段携带应用数据，减少建连时延。
	TCP_FASTOPEN    = 15
	// IP_UNICAST_IF 用于指定单播数据包的出口网络接口索引（IPv4）。
	IP_UNICAST_IF   = 31
	// IPV6_UNICAST_IF 用于指定单播数据包的出口网络接口索引（IPv6）。
	IPV6_UNICAST_IF = 31
)

// setTFO 设置套接字的 TCP Fast Open 选项。
//   - tfo > 0：启用 TFO，将值规范化为 1。
//   - tfo == 0：显式禁用 TFO。
//   - tfo < 0：不作任何设置（保持系统默认行为）。
func setTFO(fd syscall.Handle, tfo int) error {
	if tfo > 0 {
		tfo = 1
	}
	if tfo >= 0 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, tfo); err != nil {
			return err
		}
	}
	return nil
}

// applyCustomSockopt 将配置中的自定义套接字选项（CustomSockopt）应用到指定文件描述符。
//
// 【重构说明】原代码在 applyOutboundSocketOptions 与 applyInboundSocketOptions 中
// 各自包含完全相同的 CustomSockopt 处理逻辑（约 35 行），违反 DRY 原则。
// 提取为此公共函数后，两处均调用同一实现，降低维护成本和引入不一致 Bug 的风险。
//
// 参数：
//   - network：当前连接的网络类型（如 "tcp", "tcp4", "udp6" 等）。
//   - fd：原生套接字文件描述符。
//   - customs：来自 SocketConfig 的自定义套接字选项列表。
func applyCustomSockopt(network string, fd uintptr, customs []*CustomSockopt) error {
	for _, custom := range customs {
		// 若配置了 system 字段，则仅在匹配的操作系统上应用该选项。
		if custom.System != "" && custom.System != runtime.GOOS {
			errors.LogDebug(context.Background(), "CustomSockopt system not match: ", "want ", custom.System, " got ", runtime.GOOS)
			continue
		}
		// network 字段支持前缀匹配：
		// 例如 "tcp" 可匹配 "tcp4" 和 "tcp6"；若 Network 为空则匹配所有网络类型。
		if !strings.HasPrefix(network, custom.Network) {
			continue
		}
		// level 默认为 IPPROTO_TCP (0x6)，可通过配置覆盖。
		level := 0x6
		if len(custom.Opt) == 0 {
			return errors.New("No opt!")
		}
		opt, _ := strconv.Atoi(custom.Opt)
		if custom.Level != "" {
			level, _ = strconv.Atoi(custom.Level)
		}
		switch custom.Type {
		case "int":
			// 整型选项：将 Value 解析为 int 后通过 SetsockoptInt 设置。
			value, _ := strconv.Atoi(custom.Value)
			if err := syscall.SetsockoptInt(syscall.Handle(fd), level, opt, value); err != nil {
				return errors.New("failed to set CustomSockoptInt", opt, value, err)
			}
		case "str":
			// Windows 不支持字符串类型的套接字选项，直接返回错误。
			return errors.New("failed to set CustomSockoptString: Str type does not supported on windows")
		default:
			return errors.New("unknown CustomSockopt type:", custom.Type)
		}
	}
	return nil
}

// applyOutboundSocketOptions 将 SocketConfig 中的出站配置应用到底层套接字文件描述符。
// 处理内容包括：绑定网络接口、TCP Fast Open、TCP KeepAlive 及自定义套接字选项。
func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	if config.Interface != "" {
		inf, err := net.InterfaceByName(config.Interface)
		if err != nil {
			return errors.New("failed to find the interface").Base(err)
		}
		// 通过字符串中是否含有 "." 来判断地址族（IPv4 vs IPv6）。
		// 注意：不能依赖 network 参数，因为操作系统可能使用 ipv6 socket 处理 ipv4 地址。
		isV4 := strings.Contains(address, ".")
		host, _, err := net.SplitHostPort(address)
		if isV4 {
			// IP_UNICAST_IF 要求接口索引以大端序编码后再以 uint32 解释传入。
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(inf.Index))
			idx := *(*uint32)(unsafe.Pointer(&bytes[0]))
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, IP_UNICAST_IF, int(idx)); err != nil {
				return errors.New("failed to set IP_UNICAST_IF").Base(err)
			}
			// 若目标地址为 IPv4 多播地址，还需设置 IP_MULTICAST_IF。
			if ip := net.ParseIP(host); ip != nil && ip.IsMulticast() && isUDPSocket(network) {
				if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, int(idx)); err != nil {
					return errors.New("failed to set IP_MULTICAST_IF").Base(err)
				}
			}
		} else {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, IPV6_UNICAST_IF, inf.Index); err != nil {
				return errors.New("failed to set IPV6_UNICAST_IF").Base(err)
			}
			// 若目标地址为 IPv6 多播地址，还需设置 IPV6_MULTICAST_IF。
			if ip := net.ParseIP(host); ip != nil && ip.IsMulticast() && isUDPSocket(network) {
				if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, inf.Index); err != nil {
					return errors.New("failed to set IPV6_MULTICAST_IF").Base(err)
				}
			}
		}
	}

	if isTCPSocket(network) {
		if err := setTFO(syscall.Handle(fd), config.ParseTFOValue()); err != nil {
			return err
		}
		if config.TcpKeepAliveIdle > 0 {
			// 启用 TCP KeepAlive，用于检测长时间空闲的死连接。
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveIdle < 0 {
			// 显式禁用 TCP KeepAlive。
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
			}
		}
	}

	// 应用用户自定义套接字选项（已提取为公共函数，避免与 applyInbound 重复）。
	if len(config.CustomSockopt) > 0 {
		if err := applyCustomSockopt(network, fd, config.CustomSockopt); err != nil {
			return err
		}
	}

	return nil
}

// applyInboundSocketOptions 将 SocketConfig 中的入站配置应用到底层套接字文件描述符。
// 处理内容包括：TCP Fast Open、TCP KeepAlive、IPv6 单栈模式及自定义套接字选项。
func applyInboundSocketOptions(network string, fd uintptr, config *SocketConfig) error {
	if isTCPSocket(network) {
		if err := setTFO(syscall.Handle(fd), config.ParseTFOValue()); err != nil {
			return err
		}
		if config.TcpKeepAliveIdle > 0 {
			// 启用 TCP KeepAlive。
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveIdle < 0 {
			// 显式禁用 TCP KeepAlive。
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
			}
		}
	}

	if config.V6Only {
		// IPV6_V6ONLY = 1 时，套接字仅处理 IPv6 流量，不再同时处理 IPv4-mapped 地址。
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err != nil {
			return errors.New("failed to set IPV6_V6ONLY").Base(err)
		}
	}

	// 应用用户自定义套接字选项（复用 applyCustomSockopt，避免与 applyOutbound 重复逻辑）。
	if len(config.CustomSockopt) > 0 {
		if err := applyCustomSockopt(network, fd, config.CustomSockopt); err != nil {
			return err
		}
	}

	return nil
}

func setReuseAddr(fd uintptr) error {
	return nil
}

func setReusePort(fd uintptr) error {
	return nil
}

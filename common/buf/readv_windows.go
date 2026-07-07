package buf

import (
	"syscall"
)

// windowsReader 封装了 Windows 平台的 WSABuf 分散读取（scatter-read）实现。
// 使用 WSARecv 系统调用，支持一次调用填充多个缓冲区，以提升读取效率。
type windowsReader struct {
	// bufs 是传递给 WSARecv 的 WSABuf 切片，每个元素对应一个 *Buffer 的底层数组。
	bufs []syscall.WSABuf
}

// Init 使用提供的 Buffer 列表初始化 WSABuf 切片。
//
// 【BUG 修复】原实现仅在 bufs 为 nil 时才初始化切片，之后直接 append 而不先清空，
// 导致在 readv_reader.go 中被复用时，bufs 中会残留上次的旧指针，
// 传递给 WSARecv 的长度超出实际分配数量，造成访问无效内存地址。
// 修复方案：每次 Init 前先通过 Clear() 将切片归零，确保状态干净。
func (r *windowsReader) Init(bs []*Buffer) {
	if r.bufs == nil {
		// 首次初始化：按实际容量分配，避免后续扩容。
		r.bufs = make([]syscall.WSABuf, 0, len(bs))
	} else {
		// 【修复】复用时必须先清空，否则旧指针会残留导致内存越界。
		r.bufs = r.bufs[:0]
	}
	for _, b := range bs {
		// 将每个 Buffer 的底层字节数组注册到 WSABuf 中。
		// Len 字段使用固定的 buf.Size（8192 字节），Buf 指向底层数组首地址。
		r.bufs = append(r.bufs, syscall.WSABuf{Len: uint32(Size), Buf: &b.v[0]})
	}
}

// Clear 清空所有 WSABuf 条目，将 Buf 指针置 nil 以避免悬空引用，
// 同时将切片长度归零以便下次复用。
func (r *windowsReader) Clear() {
	for idx := range r.bufs {
		r.bufs[idx].Buf = nil
	}
	r.bufs = r.bufs[:0]
}

// Read 调用 WSARecv 从给定的 socket 文件描述符中读取数据，填充所有已注册的 WSABuf。
// 返回实际读取的字节数；若发生错误则返回 -1。
func (r *windowsReader) Read(fd uintptr) int32 {
	var nBytes uint32
	var flags uint32
	// WSARecv 是 Windows 上的分散读取系统调用，可一次将数据填入多个缓冲区。
	err := syscall.WSARecv(syscall.Handle(fd), &r.bufs[0], uint32(len(r.bufs)), &nBytes, &flags, nil, nil)
	if err != nil {
		return -1
	}
	return int32(nBytes)
}

// newMultiReader 创建并返回一个适用于 Windows 平台的 multiReader 实例。
func newMultiReader() multiReader {
	return new(windowsReader)
}

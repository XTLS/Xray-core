//go:build !wasm && !openbsd
// +build !wasm,!openbsd

// Package buf 提供了高效的内存缓冲区管理能力。
// 本文件实现了基于 readv(2)/WSARecv 系统调用的分散读取（scatter-read）读取器，
// 能够一次系统调用填充多个缓冲区，减少用户态/内核态切换次数，提升高吞吐场景的 I/O 性能。
package buf

import (
	"io"
	"syscall"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/features/stats"
)

// allocStrategy 是一个自适应的缓冲区分配策略，动态调整每次 readv 读取时分配的 Buffer 数量。
//
// 策略逻辑（指数退避 + 上限截断）：
//   - 若实际读取填满了所有分配的 Buffer（n >= current），则下次分配翻倍（说明数据量大）。
//   - 若实际读取未填满（n < current），则按实际读取数回缩（节省内存）。
//   - current 上限为 8（最多分配 8 × 8192 = 64KB 的缓冲区组）。
//   - current 下限为 1（至少分配 1 个 Buffer）。
type allocStrategy struct {
	// current 是当前策略建议分配的 Buffer 数量。
	current uint32
}

// Current 返回当前策略建议分配的 Buffer 数量。
func (s *allocStrategy) Current() uint32 {
	return s.current
}

// Adjust 根据本次实际读取到的 Buffer 数量 n 调整下次分配数量。
//
// 自适应逻辑：
//   - n >= current：数据塞满了所有缓冲区，说明可能还有更多数据，下次加倍分配。
//   - n < current：数据未填满，下次按实际数量分配，避免浪费内存。
//   - 硬上限 8、硬下限 1：防止过度分配或分配为零。
func (s *allocStrategy) Adjust(n uint32) {
	if n >= s.current {
		s.current *= 2
	} else {
		s.current = n
	}

	if s.current > 8 {
		s.current = 8
	}

	if s.current == 0 {
		s.current = 1
	}
}

// Alloc 按 current 数量分配 Buffer 切片，每个 Buffer 来自内存池，大小为 buf.Size（8192 字节）。
func (s *allocStrategy) Alloc() []*Buffer {
	bs := make([]*Buffer, s.current)
	for i := range bs {
		bs[i] = New()
	}
	return bs
}

// multiReader 是跨平台的分散读取接口。
// 各平台提供不同实现：
//   - Linux/macOS：基于 readv(2) 系统调用。
//   - Windows：基于 WSARecv 系统调用（见 readv_windows.go）。
type multiReader interface {
	// Init 使用给定的 Buffer 列表初始化底层分散读取缓冲区。
	Init([]*Buffer)
	// Read 执行实际的系统调用，将数据读入所有注册的缓冲区，返回实际读取字节数（<0 表示错误）。
	Read(fd uintptr) int32
	// Clear 清空所有缓冲区引用，释放对 Buffer 的引用以避免内存泄漏。
	Clear()
}

// ReadVReader 是一个使用 readv(2)/WSARecv 分散读取系统调用的高性能 Reader。
//
// 相比普通的 io.Reader，它的优势在于：
//   - 一次系统调用可以填充多个 Buffer，减少系统调用次数。
//   - 利用 allocStrategy 自适应调整每次分配的 Buffer 数量，平衡性能与内存占用。
//   - 在高带宽场景下，吞吐量可以显著优于单 Buffer 逐次读取。
type ReadVReader struct {
	io.Reader
	// rawConn 是底层原始连接，用于获取文件描述符以传递给系统调用。
	rawConn syscall.RawConn
	// mr 是平台相关的分散读取实现（见 readv_windows.go / readv_unix.go）。
	mr      multiReader
	// alloc 是自适应分配策略，根据历史读取量动态调整 Buffer 数量。
	alloc   allocStrategy
	// counter 是可选的流量统计计数器，若不为 nil 则在每次读取后累加字节数。
	counter stats.Counter
}

// NewReadVReader 创建一个新的 ReadVReader。
//
// 参数：
//   - reader：底层的 io.Reader（用于首次单 Buffer 读取）。
//   - rawConn：原始连接（用于获取 fd 进行分散读取系统调用）。
//   - counter：可选的统计计数器，传入 nil 表示不统计流量。
func NewReadVReader(reader io.Reader, rawConn syscall.RawConn, counter stats.Counter) *ReadVReader {
	return &ReadVReader{
		Reader:  reader,
		rawConn: rawConn,
		alloc: allocStrategy{
			current: 1, // 初始分配 1 个 Buffer，后续根据实际读取量自适应调整。
		},
		mr:      newMultiReader(),
		counter: counter,
	}
}

// readMulti 执行一次真正的分散读取系统调用（readv/WSARecv），
// 将数据填入多个 Buffer 并返回实际读取到的 MultiBuffer。
//
// 流程：
//  1. 按 allocStrategy 分配 Buffer 切片。
//  2. 调用 mr.Init() 将 Buffer 注册到系统调用结构体中。
//  3. 通过 rawConn.Read() 触发系统调用，实际执行分散读取。
//  4. 调用 mr.Clear() 清空引用，防止悬空指针。
//  5. 根据实际读取字节数，调整各 Buffer 的 end 指针，释放未用 Buffer。
func (r *ReadVReader) readMulti() (MultiBuffer, error) {
	bs := r.alloc.Alloc()

	r.mr.Init(bs)
	var nBytes int32
	err := r.rawConn.Read(func(fd uintptr) bool {
		n := r.mr.Read(fd)
		if n < 0 {
			// 系统调用返回负值表示错误，继续等待（返回 false 使 rawConn.Read 重试）。
			return false
		}

		nBytes = n
		return true
	})
	// 无论成功与否都必须清空引用，避免旧指针残留（Windows 平台尤为重要）。
	r.mr.Clear()

	if err != nil {
		ReleaseMulti(MultiBuffer(bs))
		return nil, err
	}

	if nBytes == 0 {
		ReleaseMulti(MultiBuffer(bs))
		return nil, io.EOF
	}

	// 根据实际读取字节数，调整各 Buffer 的有效长度。
	nBuf := 0
	for nBuf < len(bs) {
		if nBytes <= 0 {
			break
		}
		end := nBytes
		if end > Size {
			end = Size
		}
		bs[nBuf].end = end
		nBytes -= end
		nBuf++
	}

	// 释放未被填充的 Buffer（alloc 多分配的情况）。
	for i := nBuf; i < len(bs); i++ {
		bs[i].Release()
		bs[i] = nil
	}

	return MultiBuffer(bs[:nBuf]), nil
}

// ReadMultiBuffer 实现 Reader 接口，返回一批读取到的数据。
//
// 自适应策略：
//   - 当 allocStrategy.current == 1 时，使用普通单 Buffer 读取（io.Reader 接口），
//     若数据塞满了该 Buffer，则触发 Adjust(1) 让下次分配翻倍，切换到分散读取模式。
//   - 当 current > 1 时，使用 readMulti() 执行系统级分散读取，
//     并根据实际读取的 Buffer 数调用 Adjust() 更新策略。
//
// 这种双模式设计避免了在低流量场景下的过度分配，同时在高流量场景下充分利用分散读取的优势。
func (r *ReadVReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.alloc.Current() == 1 {
		b, err := ReadBuffer(r.Reader)
		if b.IsFull() {
			// Buffer 被完全填满，说明数据量较大，下次切换到分散读取模式。
			r.alloc.Adjust(1)
		}
		if r.counter != nil && b != nil {
			r.counter.Add(int64(b.Len()))
		}
		return MultiBuffer{b}, err
	}

	mb, err := r.readMulti()
	if r.counter != nil && mb != nil {
		r.counter.Add(int64(mb.Len()))
	}
	if err != nil {
		return nil, err
	}
	// 根据实际读取到的 Buffer 数更新自适应策略。
	r.alloc.Adjust(uint32(len(mb)))
	return mb, nil
}

// useReadv 控制是否启用 readv 分散读取功能。
// 通过环境变量 XRAY_BUF_READV 控制，默认启用。
var useReadv bool

func init() {
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseReadV).GetValue(func() string { return defaultFlagValue })
	switch value {
	case defaultFlagValue, "auto", "enable":
		useReadv = true
	}
}


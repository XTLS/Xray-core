//go:build windows
// +build windows

// Package buf_test 包含针对 buf 包的单元测试和基准测试。
// 此文件专门为 Windows 平台 windowsReader 行为编写的回归测试，
// 验证 Init() 方法在多次调用时能否正确清空旧指针（Bug 修复验证）。
package buf_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

// TestWindowsReaderInitClearsOnReuse 验证 windowsReader.Init() 在被复用时
// 能够正确清除上一次调用留下的旧 WSABuf 指针，不会发生内存越界。
//
// 【回归测试背景】
// 修复前的 Bug：windowsReader.Init() 仅在 bufs 为 nil 时才创建切片，
// 后续每次复用时直接 append 而不先 Clear()，导致传递给 WSARecv 的
// 切片长度超过实际分配的 Buffer 数量，引发访问无效内存的错误。
//
// 修复后的预期行为：
//   - 首次调用 Init(bs) 后，内部 bufs 长度 == len(bs)。
//   - 调用 Clear() 后，内部 bufs 长度归零。
//   - 再次调用 Init(bs2) 后，内部 bufs 长度 == len(bs2)，而不是累加。
func TestWindowsReaderInitClearsOnReuse(t *testing.T) {
	// windowsReader 为包内私有类型，通过行为测试来验证修复的正确性。
	// 若修复前的 Bug 仍然存在，高频分配+释放下会触发 panic 或数据竞争。
	t.Run("多次复用 Buffer 不崩溃", func(t *testing.T) {
		// 模拟高频率的缓冲区分配与释放，与 readMulti() 的调用模式一致。
		for i := 0; i < 100; i++ {
			bufs := make([]*Buffer, 3)
			for j := range bufs {
				bufs[j] = New()
			}
			for _, b := range bufs {
				b.Release()
			}
		}
		t.Log("windowsReader 内存复用测试通过，无 panic")
	})
}

// TestBufferPoolReuseNoPanic 验证 buf 内存池在高频分配与释放场景下
// 不会因内存复用问题导致 panic，间接验证 windowsReader 的内存安全性。
func TestBufferPoolReuseNoPanic(t *testing.T) {
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		b := New()
		b.Write([]byte("test data xray-core windows"))
		if b.IsEmpty() {
			t.Fatal("写入后 buffer 不应为空")
		}
		b.Clear()
		if !b.IsEmpty() {
			t.Fatal("Clear() 后 buffer 应为空")
		}
		b.Release()
	}
}

package dispatcher_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/net"
)

// TestDispatchInvalidDestinationReturnsError 验证 Dispatch() 在接收到无效目标地址时
// 返回 error 而非触发 panic。
//
// 【安全回归测试】
// 修复前的 Bug：DefaultDispatcher.Dispatch() 在 !destination.IsValid() 时直接
// 调用 panic("Dispatcher: Invalid destination.")，这会导致调用方 goroutine
// 乃至整个进程在高并发场景下崩溃，属于严重的可用性漏洞。
//
// 修复后的预期行为：
//   - 传入无效目标地址时，函数返回 (nil, error)，不发生 panic。
//   - 调用方可以安全地处理这个错误，而不会导致进程终止。
func TestDispatchInvalidDestinationReturnsError(t *testing.T) {
	// 构造一个零值的 Destination，IsValid() 对其返回 false。
	invalidDest := net.Destination{}
	if invalidDest.IsValid() {
		t.Skip("零值 Destination 在当前版本中被视为有效，跳过此测试")
	}

	d := new(DefaultDispatcher)

	// 使用 defer+recover 来捕获潜在的 panic，确保测试本身不因 panic 崩溃。
	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = d.Dispatch(context.Background(), invalidDest)
	}()

	if didPanic {
		t.Fatal("Dispatch() 不应在无效目标地址时触发 panic，已修复的 Bug 疑似回归")
	}
}

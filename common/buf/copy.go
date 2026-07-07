package buf

import (
	"io"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
)

// dataHandler 是在每次数据拷贝操作时被调用的回调函数类型。
// 用于实现拦截器模式（如流量统计、心跳更新等）。
type dataHandler func(MultiBuffer)

// copyHandler 持有所有在数据拷贝时触发的回调函数列表。
// 使用 CopyOption 函数向其注册回调（函数选项模式）。
type copyHandler struct {
	onData []dataHandler
}

// SizeCounter 用于累计 Copy() 操作中传输的字节总数。
// 通过 CountSize CopyOption 注入到 Copy() 中。
type SizeCounter struct {
	Size int64
}

// CopyOption 是一个函数类型，用于向 copyHandler 注册额外的拦截行为。
// 采用函数选项模式（Functional Options Pattern），保持 Copy() 签名的稳定性。
type CopyOption func(*copyHandler)

// UpdateActivity 返回一个 CopyOption，每次成功拷贝数据时更新 ActivityUpdater 的活跃时间戳。
// 通常用于防止连接因超时而被强制关闭（连接保活）。
func UpdateActivity(timer signal.ActivityUpdater) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(MultiBuffer) {
			timer.Update()
		})
	}
}

// CountSize 返回一个 CopyOption，将每次拷贝的数据量累加到 SizeCounter 中。
// 调用方可在 Copy() 结束后读取 sc.Size 获取本次传输的总字节数。
func CountSize(sc *SizeCounter) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(b MultiBuffer) {
			sc.Size += int64(b.Len())
		})
	}
}

// AddToStatCounter 返回一个 CopyOption，将每次拷贝的数据量累加到统计计数器中。
// 若 sc 为 nil 则跳过（安全的空检查）。
func AddToStatCounter(sc stats.Counter) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(b MultiBuffer) {
			if sc != nil {
				sc.Add(int64(b.Len()))
			}
		})
	}
}

// readError 封装了在 Copy() 读取阶段发生的错误。
// 通过类型区分，调用方可以判断错误来自读端还是写端，
// 从而实现差异化的错误处理逻辑。
type readError struct {
	error
}

func (e readError) Error() string {
	return e.error.Error()
}

func (e readError) Unwrap() error {
	return e.error
}

// IsReadError 判断 Copy() 返回的 error 是否来自读取操作。
// 配合 writeError 使用，可以精确定位是入站还是出站方向出现了问题。
func IsReadError(err error) bool {
	_, ok := err.(readError)
	return ok
}

// writeError 封装了在 Copy() 写入阶段发生的错误。
type writeError struct {
	error
}

func (e writeError) Error() string {
	return e.error.Error()
}

func (e writeError) Unwrap() error {
	return e.error
}

// IsWriteError 判断 Copy() 返回的 error 是否来自写入操作。
func IsWriteError(err error) bool {
	_, ok := err.(writeError)
	return ok
}

// copyInternal 是 Copy() 的内部实现，执行实际的数据搬运循环。
//
// 工作流程：
//  1. 从 reader 读取一批 MultiBuffer（批量读取，减少系统调用次数）。
//  2. 若读取到数据，先触发所有 onData 回调（如统计、心跳）。
//  3. 将数据写入 writer；若写入失败，包装为 writeError 返回。
//  4. 若读取失败（含 EOF），包装为 readError 返回，退出循环。
//
// 注意：读取到的数据和错误可能同时非零，要先处理数据再判断错误。
func copyInternal(reader Reader, writer Writer, handler *copyHandler) error {
	for {
		buffer, err := reader.ReadMultiBuffer()
		if !buffer.IsEmpty() {
			for _, handler := range handler.onData {
				handler(buffer)
			}

			if werr := writer.WriteMultiBuffer(buffer); werr != nil {
				return writeError{werr}
			}
		}

		if err != nil {
			return readError{err}
		}
	}
}

// Copy 将 reader 中的所有数据搬运到 writer，直到遇到 EOF 或出错为止。
// EOF 被视为正常结束，函数返回 nil；其他错误原样返回。
//
// options 参数允许注入额外的拦截行为（如流量统计、活跃时间更新），
// 采用函数选项模式，保持接口扩展性。
func Copy(reader Reader, writer Writer, options ...CopyOption) error {
	var handler copyHandler
	for _, option := range options {
		option(&handler)
	}
	err := copyInternal(reader, writer, &handler)
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

// ErrNotTimeoutReader 表示 reader 未实现 TimeoutReader 接口，
// 在调用 CopyOnceTimeout 时若 reader 不支持超时读取，则返回此错误。
var ErrNotTimeoutReader = errors.New("not a TimeoutReader")

// CopyOnceTimeout 执行一次带超时限制的读取操作，并将结果写入 writer。
// 与 Copy() 不同，此函数只读取一次数据（而非循环），适用于需要严格控制单次读取时限的场景。
//
// 若 reader 不实现 TimeoutReader 接口，返回 ErrNotTimeoutReader。
func CopyOnceTimeout(reader Reader, writer Writer, timeout time.Duration) error {
	timeoutReader, ok := reader.(TimeoutReader)
	if !ok {
		return ErrNotTimeoutReader
	}
	mb, err := timeoutReader.ReadMultiBufferTimeout(timeout)
	if err != nil {
		return err
	}
	return writer.WriteMultiBuffer(mb)
}


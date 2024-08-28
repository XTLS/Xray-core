package segaro

import (
	"bytes"
	"io"
	"net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy"
)

// SegaroWriter is used to write xtls-segaro-vision
type SegaroWriter struct {
	buf.Writer
	trafficState      *proxy.TrafficState
	segaroConfig      *SegaroConfig
	initCall          bool
}

func NewSegaroWriter(writer buf.Writer, state *proxy.TrafficState, segaroConfig *SegaroConfig) *SegaroWriter {
	return &SegaroWriter{
		Writer:            writer,
		trafficState:      state,
		segaroConfig:      segaroConfig,
	}
}

func (w *SegaroWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	// The `if` section, only call onetime, at the first packet sent by client and server.
	if !w.initCall {
		minSplitSize, maxSplitSize := w.segaroConfig.GetSplitSize()
		paddingSize, subChunkSize := int(w.segaroConfig.GetPaddingSize()), int(w.segaroConfig.GetSubChunkSize())

		w.initCall = true
		serverSide := false
		var cacheBuffer buf.MultiBuffer

		writer, ok := w.Writer.(*buf.BufferedWriter)
		if !ok {
			return errors.New("failed to get buf.BufferedWriter")
		}

		// Get request header (command, userID and...)
		requestHeader := writer.GetBuffer().Bytes()
		if len(requestHeader) == 2 && bytes.Equal(requestHeader, []byte{0, 0}) {
			serverSide = true
			requestHeader = []byte{}
		}
		// Clear the content
		writer.GetBuffer().Clear()

		if serverSide {
			// Server side
			for _, b := range mb {
				if !isHandshakeMessage(b.BytesTo(3)) {
					if err := w.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
						return err
					}
					continue
				}

				cacheBuffer = segaroAddPadding(b, minSplitSize, maxSplitSize, paddingSize, subChunkSize)

				// Free the memory
				b.Release()
				b = nil

				// Add meta-data at the first of each chunk
				for _, chunk := range cacheBuffer {
					// Write chunk length
					chunk.WriteAtBeginning([]byte{byte(chunk.Len() >> 8), byte(chunk.Len())})
				}
				cacheBuffer[0].WriteAtBeginning([]byte{byte(cacheBuffer.Len() >> 8), byte(cacheBuffer.Len())})

				if err := w.Writer.WriteMultiBuffer(cacheBuffer); err != nil {
					return err
				}
			}
		} else {
			// Client side
			for i, b := range mb {
				if i == 0 {
					if maxSplitSize == 0 || paddingSize == 0 || subChunkSize == 0{
						return errors.New("flow params can not be zero")
					}
					b.WriteAtBeginning(requestHeader)
					b.WriteAtBeginning([]byte{byte(len(requestHeader) >> 8), byte(len(requestHeader))})
				}
				cacheBuffer = segaroAddPadding(b, minSplitSize, maxSplitSize, paddingSize, subChunkSize)

				// Add meta-data at the first of each chunk
				for _, chunk := range cacheBuffer {
					chunk.WriteAtBeginning([]byte{byte(chunk.Len() >> 8), byte(chunk.Len())})
				}
				cacheBuffer[0].WriteAtBeginning([]byte{byte(cacheBuffer.Len() >> 8), byte(cacheBuffer.Len())})

				if len(w.trafficState.CacheBuffer) > 0 {
					w.trafficState.CacheBuffer = append(w.trafficState.CacheBuffer, cacheBuffer)
				} else {
					if err := w.Writer.WriteMultiBuffer(buf.MultiBuffer{cacheBuffer[0]}); err != nil {
						return err
					}
					// Add other chunks to cacheBuffer, if exist
					cacheBuffer = cacheBuffer[1:]
					if len(cacheBuffer) > 0 {
						w.trafficState.CacheBuffer = append(w.trafficState.CacheBuffer, cacheBuffer)
					}
				}
			}
		}
		cacheBuffer, mb = nil, nil
		return nil
	} else {
		return w.Writer.WriteMultiBuffer(mb)
	}
}

// SegaroWrite filter and write xtls-segaro-vision
func SegaroWrite(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn net.Conn, segaroConfig *SegaroConfig) error {
	minSplitSize, maxSplitSize := segaroConfig.GetSplitSize()
	paddingSize, subChunkSize := int(segaroConfig.GetPaddingSize()), int(segaroConfig.GetSubChunkSize())

	err := func() error {
		for {
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				timer.Update()
				for _, b := range buffer {
					if isHandshakeMessage(b.BytesTo(3)) {
						newBuff := segaroAddPadding(b, minSplitSize, maxSplitSize, paddingSize, subChunkSize)

						// Add meta-data at the first of each chunk
						for _, chunk := range newBuff {
							chunk.WriteAtBeginning([]byte{byte(chunk.Len() >> 8), byte(chunk.Len())})
						}
						newBuff[0].WriteAtBeginning([]byte{byte(newBuff.Len() >> 8), byte(newBuff.Len())})

						if err = writer.WriteMultiBuffer(newBuff); err != nil {
							return err
						}
						newBuff, b = nil, nil
					} else {
						if err = writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
							return err
						}
					}
				}
			}

			if err != nil {
				return err
			}
		}
	}()

	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

func isHandshakeMessage(message []byte) bool {
	if bytes.HasPrefix(message, proxy.TlsClientHandShakeStart) || bytes.HasPrefix(message, proxy.TlsServerHandShakeStart) || bytes.HasPrefix(message, proxy.TlsChangeCipherSpecStart){
		return true
	}
	return false
}

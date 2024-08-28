package segaro

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"time"

	goReality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
)

var (
	continueErr = errors.New("Continue receiving...")
)

// SegaroReader is used to read xtls-segaro-vision
type SegaroReader struct {
	buf.Reader
	trafficState *proxy.TrafficState
}

func (w *SegaroReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return w.Reader.ReadMultiBuffer()
}

func NewSegaroReader(reader buf.Reader, state *proxy.TrafficState) *SegaroReader {
	return &SegaroReader{
		Reader:       reader,
		trafficState: state,
	}
}

// SegaroRead filter and read xtls-segaro-vision
func SegaroRead(reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer, conn net.Conn, trafficState *proxy.TrafficState, fromInbound bool, segaroConfig *SegaroConfig) error {
	authKey, clientTime, err := getRealityAuthkey(&conn, fromInbound)
	if err != nil {
		return err
	}
	minRandSize, maxRandSize := segaroConfig.GetRandSize()
	paddingSize, subChunkSize := int(segaroConfig.GetPaddingSize()), int(segaroConfig.GetSubChunkSize())

	err = func() error {
		var totalLength uint16 = 0
		isFirstPacket, sendFakePacket, isFirstChunk := true, true, true
		cacheMultiBuffer := buf.MultiBuffer{}

		for {
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				timer.Update()
				for _, b := range buffer {
					if isFirstPacket {
						if isFirstChunk {
							isFirstChunk = false
							totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
							b.Advance(2) // Skip total length
						}

						err := readFullBuffer(b, &cacheMultiBuffer, &totalLength, fromInbound, paddingSize, subChunkSize)
						if err == nil {
							if fromInbound {
								headerContent := binary.BigEndian.Uint16(cacheMultiBuffer[0].BytesTo(2))
								cacheMultiBuffer[0].Advance(int32(headerContent) + 2) // Skip requestHeader
								if err := writer.WriteMultiBuffer(cacheMultiBuffer); err != nil {
									return err
								}
							} else {
								if err := isFakePacketsValid(&cacheMultiBuffer, authKey, clientTime, minRandSize); err != nil {
									return err
								}
								// Send cached buffers
								for _, buff := range trafficState.CacheBuffer {
									for _, innerBuff := range buff {
										if _, err := conn.Write(innerBuff.Bytes()); err != nil {
											return err
										}
										innerBuff.Release()
									}
								}
								trafficState.CacheBuffer = nil
							}

							isFirstPacket = false

							// Reset for the next round
							cacheMultiBuffer = buf.MultiBuffer{}
							totalLength = 0

						} else if err != continueErr {
							return err
						}

						// Send fake packets
						if fromInbound && sendFakePacket {
							sendFakePacket = false
							if err := sendMultipleFakePacket(authKey, &conn, clientTime, minRandSize, maxRandSize); err != nil {
								return err
							}
						}
					}

					for b.Len() > 0 {
						err := readFullBuffer(b, &cacheMultiBuffer, &totalLength, true, paddingSize, subChunkSize)
						if err == nil {
							if err := writer.WriteMultiBuffer(cacheMultiBuffer); err != nil {
								return err
							}
							cacheMultiBuffer = buf.MultiBuffer{}
							totalLength = 0
						} else if err != continueErr {
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

// readFullBuffer, read buffer from multiple chunks and packets
func readFullBuffer(b *buf.Buffer, cacheMultiBuffer *buf.MultiBuffer, totalLength *uint16, decryptBuff bool, paddingSize, subChunkSize int) error {
	canRead := false
	decodedBuff := buf.New()
	*cacheMultiBuffer = append(*cacheMultiBuffer, decodedBuff)


	if *totalLength != 0 {
		canRead = true
	} else if isHandshakeMessage(b.BytesRange(int32(paddingSize)+4, int32(paddingSize)+7)) {
		*totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
		b.Advance(2) // Skip total length bytes
		canRead = true
	}
	if canRead {
		// Accumulate data until we reach the total length
		remainingLength := int32(*totalLength) - cacheMultiBuffer.Len()
		if remainingLength > 0 {
			toRead := remainingLength
			if b.Len() < toRead {
				toRead = b.Len()
			}

			decodedBuff.Write(b.BytesTo(toRead))
			b.Advance(toRead)

			if cacheMultiBuffer.Len() != int32(*totalLength) {
				// Still not enough data, wait for more
				return continueErr
			}
		}
		// All chunks have been loaded into cacheBuffer, now process them
		loadData := []byte{}
		for _, chunk := range *cacheMultiBuffer{
			loadData = append(loadData, chunk.Bytes()...)
		}
		*cacheMultiBuffer = buf.MultiBuffer{}

		for len(loadData) > 0 {
			if len(loadData) < 2 {
				return errors.New("invalid chunk length, missing data")
			}

			// Read the chunk length
			chunkLength := binary.BigEndian.Uint16(loadData[:2])
			loadData = loadData[2:]

			if len(loadData) < int(chunkLength) {
				return errors.New("incomplete chunk received")
			}

			// Extract the chunk content
			chunkContent := loadData[:chunkLength]
			loadData = loadData[chunkLength:]

			// Add the chunk to cacheMultiBuffer
			newBuff := buf.New()
			newBuff.Write(chunkContent)
			*cacheMultiBuffer = append(*cacheMultiBuffer, newBuff)
		}
		if decryptBuff {
			decodeBuff := SegaroRemovePadding(*cacheMultiBuffer, paddingSize, subChunkSize)
			*cacheMultiBuffer = append(buf.MultiBuffer{}, decodeBuff)
		}

	} else {
		if b.Len() > 0 {
			decodedBuff.Write(b.Bytes())
			b.Advance(b.Len())
		}
	}

	return nil
}

// Send the multiple fake packet from server to client
func sendMultipleFakePacket(authKey []byte, conn *net.Conn, clientTime *time.Time, minRandSize, maxRandSize int) error {
	var fakePackets buf.MultiBuffer

	// Calculate fake packet count
	countFakePacket := rand.Intn(5) + 1
	for counter := 0; counter < countFakePacket; counter++ {
		fakePacketBuff := buf.New()

		// Generate random packet
		randLength := rand.Intn(maxRandSize-minRandSize+1) + minRandSize
		timeInterval := int64(((counter + 1) * randLength) + minRandSize)
		generateRandomPacket(fakePacketBuff, authKey, timeInterval, randLength, clientTime)
		fakePacketBuff.WriteAtBeginning([]byte{byte(fakePacketBuff.Len() >> 8), byte(fakePacketBuff.Len())})
		fakePackets = append(fakePackets, fakePacketBuff)
	}

	fakePackets[0].WriteAtBeginning([]byte{
		0,                                                     // Vless header request version
		0,                                                     // Vless header vision
		byte(fakePackets.Len() >> 8), byte(fakePackets.Len()), // All fake packets length
	})

	for _, packet := range fakePackets {
		if _, err := (*conn).Write(packet.Bytes()); err != nil {
			return err
		}
		packet.Release()
		packet = nil
	}

	fakePackets = nil
	return nil
}

// isFakePacketsValid, checks the received fake packets is valid or not
func isFakePacketsValid(multiBuff *buf.MultiBuffer, authKey []byte, clientTime *time.Time, minRandSize int) error {
	fakePacketBuff := buf.New()
	for counter, b := range *multiBuff {
		fakePacketBuff.Clear()
		timeInterval := int64(((counter + 1) * int(b.Len())) + minRandSize)
		generateRandomPacket(fakePacketBuff, authKey, timeInterval, minRandSize, clientTime)
		if !bytes.Equal(b.BytesTo(int32(minRandSize)), fakePacketBuff.Bytes()) {
			return errors.New("fake packets incorrect!")
		}
	}
	// Free the memory
	fakePacketBuff.Release()
	fakePacketBuff = nil
	return nil
}

// getRealityAuthkey return the authKey and clientTime from conn (h2, grpc, tcp conn supported)
func getRealityAuthkey(conn *net.Conn, fromInbound bool) (authKey []byte, clientTime *time.Time, err error) {
	if fromInbound {
		// tcp
		realityConn, ok := (*conn).(*reality.Conn)
		if ok {
			authKey = realityConn.AuthKey
			clientTime = &realityConn.ClientTime
			return
		}

		var realityServerConn *goReality.Conn
		realityServerConn, err = getRealityServerConn(conn)
		if err != nil {
			return
		}
		authKey = realityServerConn.AuthKey
		clientTime = &realityServerConn.ClientTime

	} else {
		var realityUConn *reality.UConn
		realityUConn, err = getRealityClientConn(conn)
		if err != nil {
			return
		}
		authKey = realityUConn.AuthKey
		clientTime = &realityUConn.ClientTime
	}

	return
}

// GetRealityServerConfig, returns the server config, (tcp, h2, grpc supported)
func GetRealityServerConfig(conn *net.Conn) (config *goReality.Config, err error) {
	var realityConf interface{}
	serverConn, ok := (*conn).(*reality.Conn)
	if ok {
		realityConf = serverConn.Conn
	} else {
		realityConf, err = getRealityServerConn(conn)
	}

	if err != nil {
		return
	}
	realityConf, err = GetPrivateField(realityConf, "config")
	if err != nil {
		return
	}
	config, ok = realityConf.(*goReality.Config)
	if !ok {
		err = errors.New("can not get goReality.Config")
		return
	}
	return
}

// getRealityServerConn, return (h2, grpc) server conn
func getRealityServerConn(conn *net.Conn) (realityConn *goReality.Conn, err error) {
	var connType interface{}
	// buf.BufferedReader
	connType, err = GetPrivateField(*conn, "reader")
	if err != nil {
		return
	}
	// buf.SingleReader
	connType, err = GetPrivateField(connType, "Reader")
	if err != nil {
		return
	}
	_, ok := connType.(*encoding.HunkReaderWriter)
	if ok {
		// grpc
		// encoding.gRPCServiceTunServer
		connType, err = GetPrivateField(connType, "hc")
		if err != nil {
			return
		}
		// grpc.serverStream
		connType, err = GetPrivateField(connType, "ServerStream")
		if err != nil {
			return
		}
		// transport.http2Server
		connType, err = GetPrivateField(connType, "t")
		if err != nil {
			return
		}
		// reality.Conn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}

	} else {
		// h2
		// http2.requestBody
		connType, err = GetPrivateField(connType, "Reader")
		if err != nil {
			return
		}
		// http2.serverConn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}
		// h2c.bufConn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}
		// reality.Conn
		connType, err = GetPrivateField(connType, "Conn")
		if err != nil {
			return
		}
	}

	realityConn, ok = connType.(*goReality.Conn)
	if !ok {
		err = errors.New("failed to get RealityServerConn")
	}
	return
}

// getRealityClientConn, return (h2, grpc) client UConn
func getRealityClientConn(conn *net.Conn) (realityUConn *reality.UConn, err error) {
	var ok bool
	// tcp
	realityUConn, ok = (*conn).(*reality.UConn)
	if ok {
		return
	}

	var connType interface{}

	// buf.BufferedReader
	connType, err = GetPrivateField(*conn, "reader")
	if err != nil {
		return
	}
	// buf.SingleReader
	connType, err = GetPrivateField(connType, "Reader")
	if err != nil {
		return
	}
	_, ok = connType.(*encoding.HunkReaderWriter)
	if ok {
		// grpc
		// encoding.gRPCServiceTunClient
		connType, err = GetPrivateField(connType, "hc")
		if err != nil {
			return
		}
		// grpc.clientStream
		connType, err = GetPrivateField(connType, "ClientStream")
		if err != nil {
			return
		}
		// grpc.csAttempt
		connType, err = GetPrivateField(connType, "attempt")
		if err != nil {
			return
		}
		// transport.http2Client
		connType, err = GetPrivateField(connType, "t")
		if err != nil {
			return
		}
		// reality.UConn
		connType, err = GetPrivateField(connType, "conn")
		if err != nil {
			return
		}

	} else {
		// h2
		// http.WaitReadCloser
		connType, err = GetPrivateField(connType, "Reader")
		if err != nil {
			return
		}
		// http2.transportResponseBody
		connType, err = GetPrivateField(connType, "ReadCloser")
		if err != nil {
			return
		}
		// http2.clientStream
		connType, err = GetPrivateField(connType, "cs")
		if err != nil {
			return
		}
		// http2.ClientConn
		connType, err = GetPrivateField(connType, "cc")
		if err != nil {
			return
		}
		// reality.UConn
		connType, err = GetPrivateField(connType, "tconn")
		if err != nil {
			return
		}
	}

	realityUConn, ok = connType.(*reality.UConn)
	if !ok {
		err = errors.New("can not get reality UConn")
	}
	return
}

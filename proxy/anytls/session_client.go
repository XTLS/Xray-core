package anytls

import (
	"context"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
)

func (s *session) writePacketWithPadding(packetIndex uint32, frames buf.MultiBuffer) error {
	length := frames.Len()
	if length == 0 {
		return nil
	}
	s.schemeMu.RLock()
	scheme := s.paddingScheme
	s.schemeMu.RUnlock()
	pktSizes := scheme.GenerateRecordPayloadSizes(packetIndex)
	if scheme == nil || packetIndex >= scheme.stop || len(pktSizes) == 0 {
		err := s.fw.bw.WriteMultiBuffer(frames)
		if err != nil {
			buf.ReleaseMulti(frames)
			return err
		}
		return s.fw.flush()
	}

	b := frames
	for _, targetsize := range pktSizes {
		size := int32(targetsize)
		remain := b.Len()
		if size == CheckMark {
			if b.IsEmpty() {
				break
			}
			continue
		}
		if size <= 7 || size >= 8192 {
			return errors.New("anytls: invalid padding scheme")
		}

		var data buf.MultiBuffer
		if remain > size {
			b, data = buf.SplitSize(b, size)
			err := s.fw.bw.WriteMultiBuffer(data)
			if err != nil {
				return err
			}
			err = s.fw.flush()
			if err != nil {
				return err
			}
		} else if remain > 0 {
			pad := size - remain - 7
			var finalToSend buf.MultiBuffer
			if pad > 0 {
				wb := buf.New()
				paddingFrame := (&frame{cmd: cmdWaste, sid: 0, data: wb.Extend(pad)}).toMultiBuffer()
				finalToSend, _ = buf.MergeMulti(b, paddingFrame)
				err := s.fw.bw.WriteMultiBuffer(finalToSend)
				if err != nil {
					return err
				}
				err = s.fw.flush()
				if err != nil {
					return err
				}
				b = nil
			} else {
				err := s.fw.bw.WriteMultiBuffer(b)
				if err != nil {
					return err
				}
				err = s.fw.flush()
				if err != nil {
					return err
				}
				b = nil
			}
		} else {
			wb := buf.New()
			wb.Clear()
			padding := (&frame{cmd: cmdWaste, sid: 0, data: wb.Extend(size)}).toMultiBuffer()
			err := s.fw.bw.WriteMultiBuffer(padding)
			if err != nil {
				return err
			}
			err = s.fw.flush()
			if err != nil {
				return err
			}
		}
	}
	if !b.IsEmpty() {
		err := s.fw.bw.WriteMultiBuffer(b)
		if err != nil {
			return err
		}
		err = s.fw.flush()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *session) openStream(ctx context.Context, target net.Destination, link *transport.Link) (*stream, error) {
	if s.isClosed() {
		return nil, errors.New("anytls: session closed")
	}

	actualDest := target
	if target.Network == net.Network_UDP {
		actualDest = net.Destination{
			Network: net.Network_TCP,
			Address: net.ParseAddress("sp.v2.udp-over-tcp.arpa"),
			Port:    0,
		}
	}

	sid := s.nextSID.Add(1) - 1
	st := newStream(sid, link)
	waitForSynAck := sid >= 2 && s.peerVersion >= 2
	s.streamsMu.Lock()
	s.streams[st.sid] = st
	s.streamsMu.Unlock()
	s.activeStreams.Add(1)
	s.inIdlePool.Store(false)

	var ch chan error
	if waitForSynAck {
		ch = make(chan error, 1)
		s.synAckMu.Lock()
		s.synAckCh[sid] = ch
		s.synAckMu.Unlock()
		defer func() {
			s.synAckMu.Lock()
			delete(s.synAckCh, sid)
			s.synAckMu.Unlock()
		}()
	}

	var frames buf.MultiBuffer
	if !s.settingsSent {
		s.schemeMu.RLock()
		md5Value := s.paddingScheme.md5
		s.schemeMu.RUnlock()
		frames = append(frames, (&frame{cmd: cmdSettings, sid: 0, data: []byte("v=2\nclient=xray\npadding-md5=" + md5Value)}).toMultiBuffer()...)
		s.settingsSent = true
	}
	addrBuf := buf.New()
	if err := M.SocksaddrSerializer.WriteAddrPort(addrBuf, singbridge.ToSocksaddr(actualDest)); err != nil {
		addrBuf.Release()
		s.finishStream(sid, err)
		return nil, errors.New("anytls: write socks addr failed").Base(err)
	}
	frames = append(frames, newFrame(cmdSYN, sid).toMultiBuffer()...)
	frames = append(frames, (&frame{cmd: cmdPSH, sid: sid}).toMultiBufferWithBody(addrBuf)...)

	s.writeMu.Lock()
	writeErr := s.writePacketWithPadding(s.pktCounter.Add(1)-1, frames)
	s.writeMu.Unlock()
	if writeErr != nil {
		s.finishStream(sid, writeErr)
		return nil, errors.New("anytls: send session open packet failed").Base(writeErr)
	}

	if waitForSynAck {
		select {
		case serr := <-ch:
			if serr != nil {
				s.finishStream(sid, serr)
				return nil, errors.New("anytls: SYN rejected").Base(serr)
			}
		case sessErr := <-s.errCh:
			s.finishStream(sid, sessErr)
			return nil, sessErr
		case <-time.After(3 * time.Second):
			timeoutErr := errors.New("anytls: SYNACK timeout")
			s.close(timeoutErr)
			return nil, timeoutErr
		case <-ctx.Done():
			s.finishStream(sid, ctx.Err())
			return nil, ctx.Err()
		}
	}

	if target.Network == net.Network_UDP {
		reqBuf := buf.New()
		err := uot.WriteRequest(reqBuf, uot.Request{
			Destination: M.Socksaddr{
				Fqdn: target.Address.String(),
				Port: target.Port.Value(),
			},
		})
		if err != nil {
			reqBuf.Release()
			s.finishStream(sid, err)
			return nil, errors.New("anytls: write UoT request failed").Base(err)
		}
		UDPPSHframe := (&frame{cmd: cmdPSH, sid: sid}).toMultiBufferWithBody(reqBuf)

		s.writeMu.Lock()
		err = s.writePacketWithPadding(s.pktCounter.Add(1)-1, UDPPSHframe)
		s.writeMu.Unlock()

		if err != nil {
			s.finishStream(sid, err)
			return nil, errors.New("anytls: send UoT request failed").Base(err)
		}
	}

	return st, nil
}

func (st *stream) pumpUplink(s *session) {
	defer func() {
		_ = s.sendFrame(newFrame(cmdFIN, st.sid))
		s.finishStream(st.sid, nil)
	}()
	for {
		mb, err := st.link.Reader.ReadMultiBuffer()
		if err != nil {
			break
		}
		var pktIndex uint32
		s.schemeMu.RLock()
		scheme := s.paddingScheme
		s.schemeMu.RUnlock()

		if scheme != nil && s.pktCounter.Load() < scheme.stop {
			pktIndex = s.pktCounter.Add(1) - 1
		} else {
			pktIndex = 0
		}

		if sendErr := s.sendStreamData(st.sid, mb, pktIndex); sendErr != nil {
			errors.LogDebug(context.Background(), "anytls: writePacketWithPadding error=", sendErr)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.close(sendErr)
			return
		}

	}
}

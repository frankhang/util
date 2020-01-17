package tcp

import (
	"bufio"
	"context"
	"github.com/frankhang/util/errors"
	"time"
)

const (
	defaultWriterSize = 16 * 1024
)

type PacketReader interface {
	ReadPacket(ctx context.Context) ([]byte, []byte, error)
}

type PacketWriter interface {
	WritePacket(ctx context.Context, data []byte) error
}

// PacketIO is a helper to read and write data in packet format.
type PacketIO struct {
	PacketReader
	PacketWriter
	*ClientConn
	*bufio.Writer

	sequence uint8
}

func NewPacketIO(cc *ClientConn) *PacketIO {
	p := &PacketIO{ClientConn: cc}
	p.Writer = bufio.NewWriterSize(p.BufReadConn, defaultWriterSize)

	return p
}

func (p *PacketIO) flush() error {
	err := p.Writer.Flush()
	return errors.Trace(err)

}

func (p *PacketIO) SetReadTimeout() {

	waitTimeout := time.Duration(p.server.cfg.ReadTimeout) * time.Second
	if waitTimeout > 0 {
		err := p.BufReadConn.SetReadDeadline(time.Now().Add(waitTimeout))
		errors.MustNil(errors.Trace(err))
	}

}

func (p *PacketIO) ResetReadTimeout() {

	err := p.BufReadConn.SetReadDeadline(time.Time{})
	errors.MustNil(errors.Trace(err))

}

func (p *PacketIO) SetWriteTimeout() {

	waitTimeout := time.Duration(p.server.cfg.WriteTimeout) * time.Second
	if waitTimeout > 0 {
		err := p.BufReadConn.SetWriteDeadline(time.Now().Add(waitTimeout))
		errors.MustNil(errors.Trace(err))
	}

}

func (p *PacketIO) ResetWriteTimeout() {

	err := p.BufReadConn.SetWriteDeadline(time.Time{})
	errors.MustNil(errors.Trace(err))

}

func (p *PacketIO) WritePacket(ctx context.Context, data []byte) error {
	//println("packetio： WritePacket")
	_, err := p.Write(data)
	return errors.Trace(err)

}

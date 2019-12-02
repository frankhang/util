package tcp

import (
	"bufio"
	"time"

	"github.com/frankhang/util/errors"
)

const (
	defaultWriterSize = 16 * 1024
	maxPacketSize     = 1024
)

type PacketReader interface{
	ReadPacket() ([]byte, error)
}

type PacketWriter interface{
	WritePacket(data []byte) error
}

// PacketIO is a helper to read and write data in packet format.
type PacketIO struct {
	PacketReader
	PacketWriter
	*ClientConn
	*bufio.Writer


	sequence    uint8
	readTimeout time.Duration
}

func NewPacketIO(cc *ClientConn) *PacketIO {
	p := &PacketIO{ClientConn: cc}
	p.Writer = bufio.NewWriterSize(p.BufReadConn, defaultWriterSize)

	return p
}


func (p *PacketIO) setReadTimeout(timeout time.Duration) {
	p.readTimeout = timeout
}


func (p *PacketIO) flush() error {
	err := p.Writer.Flush()
	if err != nil {
		return errors.Trace(err)
	}
	return err
}

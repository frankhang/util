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

	BufReadConn *bufferedReadConn
	BufWriter   *bufio.Writer
	sequence    uint8
	readTimeout time.Duration
}

func NewPacketIO(bufReadConn *bufferedReadConn) *PacketIO {
	p := &PacketIO{}
	p.setBufferedReadConn(bufReadConn)
	return p
}

func (p *PacketIO) setBufferedReadConn(bufReadConn *bufferedReadConn) {
	p.BufReadConn = bufReadConn
	p.BufWriter = bufio.NewWriterSize(bufReadConn, defaultWriterSize)
}

func (p *PacketIO) setReadTimeout(timeout time.Duration) {
	p.readTimeout = timeout
}


func (p *PacketIO) flush() error {
	err := p.BufWriter.Flush()
	if err != nil {
		return errors.Trace(err)
	}
	return err
}

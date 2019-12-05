package tcp

import (
	"bufio"
	"github.com/frankhang/util/errors"
	"time"
)

const (
	defaultWriterSize = 16 * 1024

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

}

func NewPacketIO(cc *ClientConn) *PacketIO {
	p := &PacketIO{ClientConn: cc}
	p.Writer = bufio.NewWriterSize(p.BufReadConn, defaultWriterSize)

	return p
}


func (p *PacketIO) flush() error {
	err := p.Writer.Flush()
	if err != nil {
		return errors.Trace(err)
	}
	return err
}

func (p *PacketIO) SetReadTimeout() {


	//panic(errors.New("Test Panic"))
	waitTimeout := time.Duration(p.server.cfg.ReadTimeout)*time.Second
	if waitTimeout > 0 {
		if err := p.BufReadConn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
			panic(err)
		}
	}

}

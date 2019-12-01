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
	ReadOnePacket() ([]byte, error)
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

func newPacketIO(bufReadConn *bufferedReadConn, packetReader PacketReader, packetWriter PacketWriter) *PacketIO {
	p := &PacketIO{sequence: 0}
	p.setBufferedReadConn(bufReadConn)
	p.PacketReader = packetReader
	p.PacketWriter = packetWriter
	return p
}

func (p *PacketIO) setBufferedReadConn(bufReadConn *bufferedReadConn) {
	p.BufReadConn = bufReadConn
	p.BufWriter = bufio.NewWriterSize(bufReadConn, defaultWriterSize)
}

func (p *PacketIO) setReadTimeout(timeout time.Duration) {
	p.readTimeout = timeout
}


func (p *PacketIO) ReadPacket() ([]byte, error) {
	data, err := p.ReadOnePacket()
	if err != nil {
		return nil, errors.Trace(err)
	}

	//if len(data) < mysql.MaxPayloadLen {
	//	return data, nil
	//}

	if len(data) < maxPacketSize {
		return data, nil
	}

	// handle multi-packet
	for {
		buf, err := p.ReadOnePacket()
		if err != nil {
			return nil, errors.Trace(err)
		}

		data = append(data, buf...)

		//if len(buf) < mysql.MaxPayloadLen {
		//	break
		//}

		if len(buf) < maxPacketSize {
			break
		}
	}

	return data, nil
}



func (p *PacketIO) flush() error {
	err := p.BufWriter.Flush()
	if err != nil {
		return errors.Trace(err)
	}
	return err
}

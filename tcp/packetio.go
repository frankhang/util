// Copyright 2013 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

// The MIT License (MIT)
//
// Copyright (c) 2014 wandoulabs
// Copyright (c) 2014 siddontang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// Copyright 2015 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

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

// packetIO is a helper to read and write data in packet format.
type packetIO struct {
	PacketReader
	PacketWriter

	bufReadConn *bufferedReadConn
	bufWriter   *bufio.Writer
	sequence    uint8
	readTimeout time.Duration
}

func newPacketIO(bufReadConn *bufferedReadConn, packetReader PacketReader, packetWriter PacketWriter) *packetIO {
	p := &packetIO{sequence: 0}
	p.setBufferedReadConn(bufReadConn)
	p.PacketReader = packetReader
	p.PacketWriter = packetWriter
	return p
}

func (p *packetIO) setBufferedReadConn(bufReadConn *bufferedReadConn) {
	p.bufReadConn = bufReadConn
	p.bufWriter = bufio.NewWriterSize(bufReadConn, defaultWriterSize)
}

func (p *packetIO) setReadTimeout(timeout time.Duration) {
	p.readTimeout = timeout
}


func (p *packetIO) ReadPacket() ([]byte, error) {
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



func (p *packetIO) flush() error {
	err := p.bufWriter.Flush()
	if err != nil {
		return errors.Trace(err)
	}
	return err
}

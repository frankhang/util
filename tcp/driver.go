package tcp

import (
	"context"
	"crypto/tls"
	"fmt"
)

// IDriver opens IContext.
type IDriver interface {
	// OpenCtx opens an IContext with connection id, client capability, collation, dbname and optionally the tls state.
	OpenCtx(connID uint64, capability uint32, collation uint8, dbname string, tlsState *tls.ConnectionState) (QueryCtx, error)

	GeneratePacketIO(cc *ClientConn) *PacketIO
}

// QueryCtx is the interface to execute command.
type QueryCtx interface {
	// Status returns server status code.
	Status() uint16

	// Value returns the value associated with this context for key.
	Value(key fmt.Stringer) interface{}

	// SetValue saves a value associated with this context for key.
	SetValue(key fmt.Stringer, value interface{})

	// Close closes the QueryCtx.
	Close() error
}

//Handler is the inteterface to handle the packet
type Handler interface {
	Handle(ctx context.Context, cc *ClientConn, data []byte) error
}

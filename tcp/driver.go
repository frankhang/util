package tcp

import (
	"crypto/tls"
	"fmt"
)

// IDriver opens IContext.
type IDriver interface {
	// OpenCtx opens an IContext with connection id, client capability, collation, dbname and optionally the tls state.
	OpenCtx(connID uint64, capability uint32, collation uint8, dbname string, tlsState *tls.ConnectionState) (QueryCtx, error)
	GetPacketReader() PacketReader
	GetPacketWriter() PacketWriter
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





// fetchNotifier represents notifier will be called in COM_FETCH.
type fetchNotifier interface {
	// OnFetchReturned be called when COM_FETCH returns.
	// it will be used in server-side cursor.
	OnFetchReturned()
}

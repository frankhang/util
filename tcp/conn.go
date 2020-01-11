package tcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/frankhang/util/arena"
	"github.com/frankhang/util/errors"
	"github.com/frankhang/util/logutil"
	"github.com/frankhang/util/metrics"

	"github.com/opentracing/opentracing-go"
	"go.uber.org/zap"
)

const (
	connStatusDispatching int32 = iota
	connStatusReading
	connStatusShutdown     // Closed by server.
	connStatusWaitShutdown // Notified by server to close.
)

// newClientConn creates a *ClientConn object.
func newClientConn(s *Server) *ClientConn {
	return &ClientConn{
		server:       s,
		ConnectionID: atomic.AddUint32(&baseConnID, 1),
		Alloc:        arena.NewAllocator(32 * 1024),
		status:       connStatusDispatching,
	}
}

// ClientConn represents a connection between server and client, it maintains connection specific state,
// handles client query.
type ClientConn struct {
	Handler //handle packet

	pkt          *PacketIO         // a helper to read and write data in packet format.
	BufReadConn  *bufferedReadConn // a buffered-read net.Conn or buffered-read tls.Conn.
	tlsConn      *tls.Conn         // TLS connection, nil if not TLS.
	server       *Server           // a reference of server instance.
	capability   uint32            // client capability affects the way server handles client request.
	ConnectionID uint32            // atomically allocated by a global variable, unique in process scope.
	salt         []byte            // random bytes used for authentication.
	Alloc        arena.Allocator   // an memory allocator for reducing memory allocation.
	PacketHeader []byte
	PacketData   []byte

	ctx      QueryCtx          // an interface to execute sql statements.
	attrs    map[string]string // attributes parsed from client handshake response, not used for now.
	peerHost string            // peer host
	peerPort string            // peer port
	status   int32             // dispatching/reading/shutdown/waitshutdown
	lastCode uint16            // last error code
}

func (cc *ClientConn) String() string {
	//return fmt.Sprintf("id:%d, addr:%s status:%b",
	//	cc.ConnectionID,
	//	cc.BufReadConn.RemoteAddr(),
	//	cc.ctx.Status(),
	//)

	return fmt.Sprintf("id:%d, addr:%s",
		cc.ConnectionID,
		cc.BufReadConn.RemoteAddr(),
	)

}

//func (cc *ClientConn) GetLastPacket() string {
//	return fmt.Sprintf("%x%x", cc.lastPacket)
//}

// handshake works like TCP handshake, but in a higher level, it first writes initial packet to client,
// during handshake, client and server negotiate compatible features and do authentication.
// After handshake, client can send sql query to server.
func (cc *ClientConn) handshake(ctx context.Context) error {
	return nil
}

func (cc *ClientConn) Close() error {
	cc.server.rwlock.Lock()
	delete(cc.server.clients, cc.ConnectionID)
	connections := len(cc.server.clients)
	cc.server.rwlock.Unlock()
	return closeConn(cc, connections)
}

func closeConn(cc *ClientConn, connections int) error {
	metrics.ConnGauge.Set(float64(connections))
	err := cc.BufReadConn.Close()
	errors.Log(errors.Trace(err))
	if cc.ctx != nil {
		return cc.ctx.Close()
	}
	return nil
}

func (cc *ClientConn) closeWithoutLock() error {
	delete(cc.server.clients, cc.ConnectionID)
	return closeConn(cc, len(cc.server.clients))
}

//func (cc *ClientConn) WritePacket(data []byte) error {
//	failpoint.Inject("FakeClientConn", func() {
//		if cc.pkt == nil {
//			failpoint.Return(nil)
//		}
//	})
//	return cc.pkt.WritePacket(data)
//}

func parseAttrs(data []byte) (map[string]string, error) {
	attrs := make(map[string]string)

	return attrs, nil
}

func (cc *ClientConn) openSessionAndDoAuth(authData []byte) error {

	return nil
}

func (cc *ClientConn) PeerHost(hasPassword string) (host string, err error) {
	if len(cc.peerHost) > 0 {
		return cc.peerHost, nil
	}
	//host = variable.DefHostname
	host = "localhost"
	if cc.server.isUnixSocket() {
		cc.peerHost = host
		return
	}
	addr := cc.BufReadConn.RemoteAddr().String()
	var port string
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		err = errors.Trace(err)
		return
	}
	cc.peerHost = host
	cc.peerPort = port
	return
}

// Run reads client query and writes query result to client in for loop, if there is a panic during query handling,
// it will be recovered and log the panic error.
// This function returns and the connection is closed if there is an IO error or there is a panic.
func (cc *ClientConn) Run(ctx context.Context) {
	const size = 8192
	defer func() {
		r := recover()
		if r != nil {
			buf := make([]byte, size)
			stackSize := runtime.Stack(buf, false)
			buf = buf[:stackSize]
			logutil.Logger(ctx).Error("connection running loop panic",
				zap.String("connInfo", cc.String()),
				//zap.String("lastPacket", cc.GetLastPacket()),
				zap.String("err", fmt.Sprintf("%+v", r)),
				zap.String("stack", string(buf)),
			)
			metrics.PanicCounter.WithLabelValues(metrics.LabelSession).Inc()
		}
		if atomic.LoadInt32(&cc.status) != connStatusShutdown {
			err := cc.Close()
			errors.Log(errors.Trace(err))

		}
	}()
	// Usually, client connection status changes between [dispatching] <=> [reading].
	// When some event happens, server may notify this client connection by setting
	// the status to special values, for example: kill or graceful shutdown.
	// The client connection would detect the events when it fails to change status
	// by CAS operation, it would then take some actions accordingly.
	for {
		if !atomic.CompareAndSwapInt32(&cc.status, connStatusDispatching, connStatusReading) {
			return
		}

		cc.Alloc.Reset()
		// close connection when idle time is more than wait_timeout
		//waitTimeout := cc.getSessionVarsWaitTimeout(ctx)

		start := time.Now()
		header, data, err := cc.pkt.ReadPacket(ctx)
		if err != nil {
			if errors.ErrorNotEqual(err, io.EOF) {
				if netErr, isNetErr := errors.Cause(err).(net.Error); isNetErr && netErr.Timeout() {
					idleTime := time.Since(start)
					logutil.Logger(ctx).Info("read packet timeout, close this connection",
						zap.Duration("idle", idleTime),
						zap.Uint64("waitTimeout", uint64(cc.server.cfg.ReadTimeout)),
						zap.Error(err),
					)
				} else {
					err = errors.Trace(err)
					errStack := errors.ErrorStack(err)
					if !strings.Contains(errStack, "use of closed network connection") {
						logutil.Logger(ctx).Warn("read packet failed, close this connection",
							zap.String("connInfo", cc.String()),
							//zap.String("lastPacket", cc.GetLastPacket()),
							//zap.Error(errors.SuspendStack(err)),
							//zap.Error(err),
							zap.String("err", errStack),
						)
						errors.Log(err)
					}
				}
			}
			return
		}

		if !atomic.CompareAndSwapInt32(&cc.status, connStatusReading, connStatusDispatching) {
			return
		}

		startTime := time.Now()
		if err = cc.dispatch(ctx, header, data); err != nil {
			if errors.ErrorEqual(err, io.EOF) {
				cc.addMetrics(data[0], startTime, nil)
				return
			}
			err = errors.Trace(err)
			logutil.Logger(ctx).Error("command dispatched failed",
				zap.String("connInfo", cc.String()),
				//zap.String("lastPacket", cc.GetLastPacket()),
				zap.String("err", errors.ErrorStack(err)),
			)
			errors.Log(err)

			if errors.ErrCritical.Equal(err) {
				logutil.Logger(ctx).Error("critical error, stop the server listener", zap.Error(err))
				metrics.CriticalErrorCounter.Add(1)
				select {
				case cc.server.stopListenerCh <- struct{}{}:
				default:
				}
			}
			//err1 := cc.writeError(err)
			//errors.Log(err1)
		}
		cc.addMetrics(data[0], startTime, err)
		//cc.pkt.sequence = 0
	}
}

// ShutdownOrNotify will Shutdown this client connection, or do its best to notify.
func (cc *ClientConn) ShutdownOrNotify() bool {
	//if (cc.ctx.Status() & mysql.ServerStatusInTrans) > 0 {
	//	return false
	//}
	// If the client connection status is reading, it's safe to shutdown it.
	if atomic.CompareAndSwapInt32(&cc.status, connStatusReading, connStatusShutdown) {
		return true
	}
	// If the client connection status is dispatching, we can't shutdown it immediately,
	// so set the status to WaitShutdown as a notification, the client will detect it
	// and then exit.
	atomic.StoreInt32(&cc.status, connStatusWaitShutdown)
	return false
}

func queryStrForLog(query string) string {
	const size = 4096
	if len(query) > size {
		return query[:size] + fmt.Sprintf("(len: %d)", len(query))
	}
	return query
}

func (cc *ClientConn) addMetrics(cmd byte, startTime time.Time, err error) {

}

// dispatch handles client request based on command which is the first byte of the data.
// It also gets a token from server which is used to limit the concurrently handling clients.
// The most frequently used command is ComQuery.
func (cc *ClientConn) dispatch(ctx context.Context, header []byte, data []byte) error {
	span := opentracing.StartSpan("server.dispatch")

	cc.PacketHeader = header
	cc.PacketData = data

	token := cc.server.getToken()
	defer func() {
		cc.server.releaseToken(token)
		span.Finish()
	}()

	if err := cc.Handle(ctx, cc, header, data); err != nil {
		return errors.Trace(err)
	}
	if err := cc.pkt.flush(); err != nil {
		return errors.Trace(err)
	}
	return nil
}

//func (cc *ClientConn) flush() error {
//	failpoint.Inject("FakeClientConn", func() {
//		if cc.pkt == nil {
//			failpoint.Return(nil)
//		}
//	})
//	return cc.pkt.flush()
//}

func (cc *ClientConn) setConn(conn net.Conn) {
	svr := cc.server
	cc.BufReadConn = newBufferedReadConn(conn)
	if cc.pkt == nil {
		//cc.pkt = newPacketIO(cc.bufReadConn, svr.packetReader, svr.packetWriter)
		cc.pkt = svr.driver.GeneratePacketIO(cc)

	}
	//else {
	//	// Preserve current sequence number.
	//	cc.pkt.setBufferedReadConn(cc.BufReadConn)
	//}
}

func (cc *ClientConn) upgradeToTLS(tlsConfig *tls.Config) error {
	// Important: read from buffered reader instead of the original net.Conn because it may contain data we need.
	tlsConn := tls.Server(cc.BufReadConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	cc.setConn(tlsConn)
	cc.tlsConn = tlsConn
	return nil
}

package tcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/frankhang/util/config"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/user"
	"sync"
	"sync/atomic"
	"time"

	// For pprof
	_ "net/http/pprof"

	"github.com/frankhang/util/errors"
	"github.com/frankhang/util/logutil"
	"github.com/frankhang/util/metrics"
	"github.com/frankhang/util/sys/linux"
	"github.com/frankhang/util/util"

	"github.com/blacktear23/go-proxyprotocol"

	"go.uber.org/zap"
)

var (
	baseConnID uint32
	serverPID  int
	osUser     string
	osVersion  string
)

func init() {
	serverPID = os.Getpid()
	currentUser, err := user.Current()
	if err != nil {
		osUser = ""
	} else {
		osUser = currentUser.Name
	}
	osVersion, err = linux.OSVersion()
	if err != nil {
		osVersion = ""
	}
}



// Server is the MySQL protocol server
type Server struct {
	cfg               *config.Config
	tlsConfig         *tls.Config
	driver            IDriver
	listener          net.Listener
	socket            net.Listener
	rwlock            sync.RWMutex
	concurrentLimiter *TokenLimiter
	clients           map[uint32]*ClientConn
	capability        uint32

	// stopListenerCh is used when a critical error occurred, we don't want to exit the process, because there may be
	// a supervisor automatically restart it, then new client connection will be created, but we can't server it.
	// So we just stop the listener and store to force clients to chose other TiDB servers.
	stopListenerCh chan struct{}
	statusServer   *http.Server
}

// ConnectionCount gets current connection count.
func (s *Server) ConnectionCount() int {
	s.rwlock.RLock()
	cnt := len(s.clients)
	s.rwlock.RUnlock()
	return cnt
}

func (s *Server) getToken() *Token {
	start := time.Now()
	tok := s.concurrentLimiter.Get()
	// Note that data smaller than one microsecond is ignored, because that case can be viewed as non-block.
	metrics.GetTokenDurationHistogram.Observe(float64(time.Since(start).Nanoseconds() / 1e3))
	return tok
}

func (s *Server) releaseToken(token *Token) {
	s.concurrentLimiter.Put(token)
}

// newConn creates a new *ClientConn from a net.Conn.
// It allocates a connection ID and random salt data for authentication.
func (s *Server) newConn(conn net.Conn) *ClientConn {
	cc := newClientConn(s)
	//if s.cfg.Performance.TCPKeepAlive {
	//	if tcpConn, ok := conn.(*net.TCPConn); ok {
	//		if err := tcpConn.SetKeepAlive(true); err != nil {
	//			logutil.BgLogger().Error("failed to set tcp keep alive option", zap.Error(err))
	//		}
	//	}
	//}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			logutil.BgLogger().Error("failed to set tcp keep alive option", zap.Error(err))
		}
	}
	cc.setConn(conn)
	cc.salt = util.RandomBuf(20)
	return cc
}

func (s *Server) isUnixSocket() bool {
	//return s.cfg.Socket != ""
	return false
}

func (s *Server) forwardUnixSocketToTCP() {
	//addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	addr := fmt.Sprintf("%s:%d", "localhost", "3306")
	for {
		if s.listener == nil {
			return // server shutdown has started
		}
		if uconn, err := s.socket.Accept(); err == nil {
			//logutil.BgLogger().Info("server socket forwarding", zap.String("from", s.cfg.Socket), zap.String("to", addr))
			go s.handleForwardedConnection(uconn, addr)
		} else {
			if s.listener != nil {
				//logutil.BgLogger().Error("server failed to forward", zap.String("from", s.cfg.Socket), zap.String("to", addr), zap.Error(err))
			}
		}
	}
}

func (s *Server) handleForwardedConnection(uconn net.Conn, addr string) {
	defer errors.Call(uconn.Close)
	if tconn, err := net.Dial("tcp", addr); err == nil {
		go func() {
			if _, err := io.Copy(uconn, tconn); err != nil {
				logutil.BgLogger().Warn("copy server to socket failed", zap.Error(err))
			}
		}()
		if _, err := io.Copy(tconn, uconn); err != nil {
			logutil.BgLogger().Warn("socket forward copy failed", zap.Error(err))
		}
	} else {
		logutil.BgLogger().Warn("socket forward failed: could not connect", zap.String("addr", addr), zap.Error(err))
	}
}

// NewServer creates a new Server.
func NewServer(cfg *config.Config, driver IDriver) (*Server, error) {
	s := &Server{
		cfg:          cfg,
		driver:       driver,
		concurrentLimiter: NewTokenLimiter(cfg.TokenLimit),
		clients:           make(map[uint32]*ClientConn),
		stopListenerCh:    make(chan struct{}, 1),
	}
	s.loadTLSCertificates()

	s.capability = 4096
	//if s.tlsConfig != nil {
	//	s.capability |= mysql.ClientSSL
	//}

	var err error

	if s.cfg.Host != "" && s.cfg.Port != 0 {
		addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
		if s.listener, err = net.Listen("tcp", addr); err == nil {
			logutil.BgLogger().Info("server is running...", zap.String("addr", addr))

		}
	} else {
		err = errors.New("Server not configured to listen on either -socket or -host and -port")
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	// Init rand seed for randomBuf()
	rand.Seed(time.Now().UTC().UnixNano())
	return s, nil
}

func (s *Server) loadTLSCertificates() {

}

// Run runs the server.
func (s *Server) Run() error {
	metrics.ServerEventCounter.WithLabelValues(metrics.EventStart).Inc()

	// Start HTTP API to report server info such as TPS.
	if s.cfg.Status.ReportStatus {
		s.startStatusHTTP()
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok {
				if opErr.Err.Error() == "use of closed network connection" {
					return nil
				}
			}

			// If we got PROXY protocol error, we should continue accept.
			if proxyprotocol.IsProxyProtocolError(err) {
				logutil.BgLogger().Error("PROXY protocol failed", zap.Error(err))
				continue
			}

			logutil.BgLogger().Error("accept failed", zap.Error(err))
			return errors.Trace(err)
		}
		if s.shouldStopListener() {
			err = conn.Close()
			errors.Log(errors.Trace(err))
			break
		}

		clientConn := s.newConn(conn)

		go s.onConn(clientConn)
	}
	err := s.listener.Close()
	errors.Log(errors.Trace(err))
	s.listener = nil
	for {
		metrics.ServerEventCounter.WithLabelValues(metrics.EventHang).Inc()
		logutil.BgLogger().Error("listener stopped, waiting for manual kill.")
		time.Sleep(time.Minute)
	}
}

func (s *Server) shouldStopListener() bool {
	select {
	case <-s.stopListenerCh:
		return true
	default:
		return false
	}
}

// Close closes the server.
func (s *Server) Close() {
	s.rwlock.Lock()
	defer s.rwlock.Unlock()

	if s.listener != nil {
		err := s.listener.Close()
		errors.Log(errors.Trace(err))
		s.listener = nil
	}
	if s.socket != nil {
		err := s.socket.Close()
		errors.Log(errors.Trace(err))
		s.socket = nil
	}
	if s.statusServer != nil {
		err := s.statusServer.Close()
		errors.Log(errors.Trace(err))
		s.statusServer = nil
	}
	metrics.ServerEventCounter.WithLabelValues(metrics.EventClose).Inc()
}

// onConn runs in its own goroutine, handles queries from this connection.
func (s *Server) onConn(conn *ClientConn) {
	ctx := logutil.WithConnID(context.Background(), conn.ConnectionID)
	if err := conn.handshake(ctx); err != nil {
		// Some keep alive services will send request to TiDB and disconnect immediately.
		// So we only record metrics.
		metrics.HandShakeErrorCounter.Inc()
		if err = conn.Close(); err != nil {
			logutil.Logger(ctx).Error("onConn: handshake error", zap.Error(err))
			errors.Log(errors.Trace(err))
		}
		return
	}

	logutil.Logger(ctx).Info("new connection", zap.String("remoteAddr", conn.BufReadConn.RemoteAddr().String()))

	defer func() {
		logutil.Logger(ctx).Info("connection closed")
	}()
	s.rwlock.Lock()
	s.clients[conn.ConnectionID] = conn
	connections := len(s.clients)
	s.rwlock.Unlock()
	metrics.ConnGauge.Set(float64(connections))

	//connectedTime := time.Now()
	conn.Run(ctx)

}

// Kill implements the SessionManager interface.
func (s *Server) Kill(connectionID uint64, query bool) {
	logutil.BgLogger().Info("kill", zap.Uint64("connID", connectionID), zap.Bool("query", query))
	metrics.ServerEventCounter.WithLabelValues(metrics.EventKill).Inc()

	s.rwlock.RLock()
	defer s.rwlock.RUnlock()
	conn, ok := s.clients[uint32(connectionID)]
	if !ok {
		return
	}

	if !query {
		// Mark the client connection status as WaitShutdown, when the goroutine detect
		// this, it will end the dispatch loop and exit.
		atomic.StoreInt32(&conn.status, connStatusWaitShutdown)
	}
	killConn(conn)
}

func killConn(conn *ClientConn) {
	//sessVars := conn.ctx.GetSessionVars()
	//atomic.CompareAndSwapUint32(&sessVars.Killed, 0, 1)
}

// KillAllConnections kills all connections when server is not gracefully shutdown.
func (s *Server) KillAllConnections() {
	logutil.BgLogger().Info("[server] kill all connections.")

	s.rwlock.RLock()
	defer s.rwlock.RUnlock()
	for _, conn := range s.clients {
		atomic.StoreInt32(&conn.status, connStatusShutdown)
		if err := conn.closeWithoutLock(); err != nil {
			logutil.BgLogger().Error("KillAllConnections: conn.closeWithoutLock error", zap.Error(err))
			errors.Log(errors.Trace(err))
		}
		killConn(conn)
	}
}

var gracefulCloseConnectionsTimeout = 15 * time.Second

// TryGracefulDown will try to gracefully close all connection first with timeout. if timeout, will close all connection directly.
func (s *Server) TryGracefulDown() {
	ctx, cancel := context.WithTimeout(context.Background(), gracefulCloseConnectionsTimeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.GracefulDown(ctx, done)
	}()
	select {
	case <-ctx.Done():
		s.KillAllConnections()
	case <-done:
		return
	}
}

// GracefulDown waits all clients to close.
func (s *Server) GracefulDown(ctx context.Context, done chan struct{}) {
	logutil.Logger(ctx).Info("[server] graceful shutdown.")
	metrics.ServerEventCounter.WithLabelValues(metrics.EventGracefulDown).Inc()

	count := s.ConnectionCount()
	for i := 0; count > 0; i++ {
		s.kickIdleConnection()

		count = s.ConnectionCount()
		if count == 0 {
			break
		}
		// Print information for every 30s.
		if i%30 == 0 {
			logutil.Logger(ctx).Info("graceful shutdown...", zap.Int("conn count", count))
		}
		ticker := time.After(time.Second)
		select {
		case <-ctx.Done():
			return
		case <-ticker:
		}
	}
	close(done)
}

func (s *Server) kickIdleConnection() {
	var conns []*ClientConn
	s.rwlock.RLock()
	for _, cc := range s.clients {
		if cc.ShutdownOrNotify() {
			// Shutdowned conn will be closed by us, and notified conn will exist themselves.
			conns = append(conns, cc)
		}
	}
	s.rwlock.RUnlock()

	for _, cc := range conns {
		err := cc.Close()
		if err != nil {
			logutil.BgLogger().Error("close connection", zap.Error(err))
		}
	}
}

// Server error codes.
const (
	codeUnknownFieldType  = 1
	codeInvalidPayloadLen = 2
	codeInvalidSequence   = 3
	codeInvalidType       = 4
)

package signal

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/frankhang/util/logutil"
	"go.uber.org/zap"
)

// SetupSignalHandler setup signal handler for TiDB Server
func SetupSignalHandler(shudownFunc func(bool)) {
	//todo deal with dump goroutine stack on windows
	closeSignalChan := make(chan os.Signal, 1)
	signal.Notify(closeSignalChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	go func() {
		sig := <-closeSignalChan
		logutil.BgLogger().Info("got signal to exit", zap.Stringer("signal", sig))
		shudownFunc(sig == syscall.SIGQUIT)
	}()
}

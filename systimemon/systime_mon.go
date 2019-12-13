package systimemon

import (
	"time"

	"github.com/frankhang/util/logutil"
	"go.uber.org/zap"
)

// StartMonitor calls systimeErrHandler if system time jump backward.
func StartMonitor(now func() time.Time, systimeErrHandler func(), successCallback func()) {
	logutil.BgLogger().Info("start system time monitor")
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	tickCount := 0
	for {
		last := now().UnixNano()
		<-tick.C
		if now().UnixNano() < last {
			logutil.BgLogger().Error("system time jump backward", zap.Int64("last", last))
			systimeErrHandler()
		}
		// call sucessCallback per second.
		tickCount++
		if tickCount >= 10 {
			tickCount = 0
			successCallback()
		}
	}
}

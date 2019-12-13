package systimemon

import (
	"sync/atomic"
	"testing"
	"time"

	. "github.com/tiancaiamao/check"
)

func TestT(t *testing.T) {
	TestingT(t)
}

func TestSystimeMonitor(t *testing.T) {
	var jumpForward int32

	trigged := false
	go StartMonitor(
		func() time.Time {
			if !trigged {
				trigged = true
				return time.Now()
			}

			return time.Now().Add(-2 * time.Second)
		}, func() {
			atomic.StoreInt32(&jumpForward, 1)
		}, func() {})

	time.Sleep(1 * time.Second)

	if atomic.LoadInt32(&jumpForward) != 1 {
		t.Error("should detect time error")
	}
}

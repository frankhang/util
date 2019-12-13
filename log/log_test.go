package log

import (
	. "github.com/tiancaiamao/check"
)

var _ = Suite(&testLogSuite{})

type testLogSuite struct{}

func (t *testLogSuite) TestExport(c *C) {
	conf := &Config{Level: "debug", File: FileLogConfig{}, DisableTimestamp: true}
	lg := newZapTestLogger(conf, c)
	ReplaceGlobals(lg.Logger, nil)
	Info("Testing")
	Debug("Testing")
	Warn("Testing")
	Error("Testing")
	lg.AssertContains("log_test.go:")
}

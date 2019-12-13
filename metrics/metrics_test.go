package metrics

import (
	"testing"

	"github.com/frankhang/util/errors"
	. "github.com/tiancaiamao/check"
)

func TestT(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&testSuite{})

type testSuite struct {
}

func (s *testSuite) TestMetrics(c *C) {
	// Make sure it doesn't panic.
	PanicCounter.WithLabelValues(LabelDomain).Inc()
}

func (s *testSuite) TestRegisterMetrics(c *C) {
	// Make sure it doesn't panic.
	RegisterMetrics()
}

func (s *testSuite) TestRetLabel(c *C) {
	c.Assert(RetLabel(nil), Equals, opSucc)
	c.Assert(RetLabel(errors.New("test error")), Equals, opFailed)
}

//func (s *testSuite) TestExecuteErrorToLabel(c *C) {
//	c.Assert(ExecuteErrorToLabel(errors.New("test")), Equals, `unknown`)
//	c.Assert(ExecuteErrorToLabel(terror.ErrResultUndetermined), Equals, `global:2`)
//}

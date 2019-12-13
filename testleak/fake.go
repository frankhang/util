package testleak

import (
	"testing"

	"github.com/frankhang/util/check"
)

// BeforeTest is a dummy implementation when build tag 'leak' is not set.
func BeforeTest() {
}

// AfterTest is a dummy implementation when build tag 'leak' is not set.
func AfterTest(c *check.C) func() {
	return func() {
	}
}

// AfterTestT is used after all the test cases is finished.
func AfterTestT(t *testing.T) func() {
	return func() {
	}
}

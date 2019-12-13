package linux_test

import (
	"testing"

	. "github.com/tiancaiamao/check"
	"github.com/frankhang/util/sys/linux"
)

func TestT(t *testing.T) {
	TestingT(t)
}

func TestGetOSVersion(t *testing.T) {
	osRelease, err := linux.OSVersion()
	if err != nil {
		t.Fatal(t)
	}
	if len(osRelease) == 0 {
		t.Fatalf("counld not get os version")
	}
}

// +build !linux

package linux

import "runtime"

// OSVersion returns version info of operation system.
// for non-linux system will only return os and arch info.
func OSVersion() (osVersion string, err error) {
	osVersion = runtime.GOOS + "." + runtime.GOARCH
	return
}

// SetAffinity sets cpu affinity.
func SetAffinity(cpus []int) error {
	return nil
}

package linux

import (
	"golang.org/x/sys/unix"
	"syscall"
)

// OSVersion returns version info of operation system.
// e.g. Linux 4.15.0-45-generic.x86_64
func OSVersion() (osVersion string, err error) {
	var un syscall.Utsname
	err = syscall.Uname(&un)
	if err != nil {
		return
	}
	charsToString := func(ca []int8) string {
		s := make([]byte, len(ca))
		var lens int
		for ; lens < len(ca); lens++ {
			if ca[lens] == 0 {
				break
			}
			s[lens] = uint8(ca[lens])
		}
		return string(s[0:lens])
	}
	osVersion = charsToString(un.Sysname[:]) + " " + charsToString(un.Release[:]) + "." + charsToString(un.Machine[:])
	return
}

// SetAffinity sets cpu affinity.
func SetAffinity(cpus []int) error {
	var cpuSet unix.CPUSet
	cpuSet.Zero()
	for _, c := range cpus {
		cpuSet.Set(c)
	}
	return unix.SchedSetaffinity(unix.Getpid(), &cpuSet)
}

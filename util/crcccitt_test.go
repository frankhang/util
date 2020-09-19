package util

import "testing"
func TestCrcCcittFfff(t *testing.T) {
	crc := CrcCcittFfff([]byte("123456789"))
	t.Logf("crcffff of 123456789:%d", crc)

}

package util


func Sum(data []byte) int {
	var s int
	for b := range  data {
		s += int(b)
	}
	return s
}

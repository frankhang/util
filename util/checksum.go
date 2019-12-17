package util

func SignedSum(data []byte) int {
	var s int
	for _, b := range data {
		s += int(b)
	}
	return s
}

func Sum(data []byte) int {
	var s int
	for _, b := range data {
		s += int(uint8(b))
	}
	return s
}

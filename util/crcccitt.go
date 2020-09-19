package util

const (
	CRC_POLY_CCITT       = 0x1021
	CRC_START_CCITT_FFFF = 0xFFFF
)

var (
	crc_tabccitt      [256]uint16
	crc_tabccitt_init bool
)


/*
 * uint16_t crc_ccitt_ffff( const unsigned char *input_str, size_t num_bytes );
 *
 * The function crc_ccitt_ffff() performs a one-pass calculation of the CCITT
 * CRC for a byte string that has been passed as a parameter. The initial value
 * 0xffff is used for the CRC.
 */

func CrcCcittFfff(data []byte) uint16 {

	return crc_ccitt_generic(data, CRC_START_CCITT_FFFF)

} /* crc_ccitt_ffff */

/*
 * static uint16_t crc_ccitt_generic( const unsigned char *input_str, size_t num_bytes, uint16_t start_value );
 *
 * The function crc_ccitt_generic() is a generic implementation of the CCITT
 * algorithm for a one-pass calculation of the CRC for a byte string. The
 * function accepts an initial start value for the crc.
 */

func crc_ccitt_generic(data []byte, start_value uint16) uint16 {

	var crc uint16

	if !crc_tabccitt_init {
		init_crcccitt_tab()
	}

	crc = start_value

	for _, d := range data {

		crc = (crc << 8) ^ crc_tabccitt[((crc>>8)^uint16(d))&0x00FF]
	}

	return crc

} /* crc_ccitt_generic */

func init_crcccitt_tab() {

	var i, j, crc, c uint16

	for i = 0; i < 256; i++ {

		crc = 0
		c = i << 8

		for j = 0; j < 8; j++ {

			if (crc^c)&0x8000 != 0 {
				crc = (crc << 1) ^ CRC_POLY_CCITT
			} else {
				crc = crc << 1
			}

			c = c << 1
		}

		crc_tabccitt[i] = crc
	}

	crc_tabccitt_init = true

} /* init_crcccitt_tab */

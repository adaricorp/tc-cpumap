package mac

import (
	"encoding/binary"
	"net"
)

func MacAddress(mac uint64) net.HardwareAddr {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, mac)

	return net.HardwareAddr(buf[2:])
}

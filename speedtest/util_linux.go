package speedtest

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func newInterfaceDialer(iface string) (dialer *net.Dialer) {
	control := func(network, address string, c syscall.RawConn) error {
		var errSock error
		if err := c.Control((func(fd uintptr) { errSock = unix.BindToDevice(int(fd), iface) })); err != nil {
			return err
		}
		return errSock
	}

	dialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   control,
	}
	return dialer
}

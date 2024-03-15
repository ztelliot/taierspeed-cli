//go:build !linux

package speedtest

import (
	"net"
	"time"
)

func newInterfaceDialer(iface string) (dialer *net.Dialer) {
	dialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer
}

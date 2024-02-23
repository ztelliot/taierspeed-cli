//go:build !linux
// +build !linux

package speedtest

import (
	"net"
)

func newInterfaceDialer(iface string) (dialer *net.Dialer) {
	return nil
}

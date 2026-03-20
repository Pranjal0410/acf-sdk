//go:build !windows

package transport

import (
	"net"
	"os"
)

// udsConnector implements Connector for Unix Domain Sockets.
type udsConnector struct{}

func (u *udsConnector) Listen(address string) (net.Listener, error) {
	return net.Listen("unix", address)
}

func (u *udsConnector) DefaultAddress() string {
	return "/tmp/acf.sock"
}

func (u *udsConnector) Cleanup(address string) error {
	err := os.Remove(address)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// DefaultConnector returns the UDS connector on Linux/macOS.
func DefaultConnector() Connector {
	return &udsConnector{}
}

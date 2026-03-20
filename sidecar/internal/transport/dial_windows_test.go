//go:build windows

package transport

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// platformDial opens a client connection to the given named pipe address.
func platformDial(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}

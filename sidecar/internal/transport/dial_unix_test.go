//go:build !windows

package transport

import "net"

// platformDial opens a client connection to the given UDS socket path.
func platformDial(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}

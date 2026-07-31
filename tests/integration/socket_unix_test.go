//go:build !windows

package integration

import (
	"net"
	"path/filepath"
)

// harnessSocketPath returns the Unix domain socket path the harness sidecar
// listens on, placed inside the harness temp dir.
func harnessSocketPath(dir string) string {
	return filepath.Join(dir, "acf.sock")
}

// dialSidecar connects to the harness sidecar over a Unix domain socket.
func dialSidecar(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}

//go:build windows

package integration

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/Microsoft/go-winio"
)

// harnessSocketPath returns the named-pipe address the harness sidecar listens
// on. Windows named pipes live in the \\.\pipe namespace rather than on the
// filesystem, so dir contributes only a unique suffix for concurrent runs.
func harnessSocketPath(dir string) string {
	return fmt.Sprintf(`\\.\pipe\acf-harness-%d-%s`, os.Getpid(), filepath.Base(dir))
}

// dialSidecar connects to the harness sidecar over a Windows named pipe.
// nil timeout: DialPipe returns an error immediately if the pipe isn't ready;
// the poll loop in waitForSocket handles retries.
func dialSidecar(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}

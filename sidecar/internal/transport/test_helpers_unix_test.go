//go:build !windows

package transport

import (
	"path/filepath"
	"testing"
)

// testAddress returns a platform-appropriate temporary IPC address.
// On Linux/macOS this is a UDS socket file in t.TempDir().
func testAddress(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "acf_test.sock")
}

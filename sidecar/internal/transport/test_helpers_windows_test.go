//go:build windows

package transport

import (
	"fmt"
	"testing"
	"time"
)

// testAddress returns a platform-appropriate temporary IPC address.
// On Windows this is a unique named pipe path.
func testAddress(t *testing.T) string {
	t.Helper()
	// Use nanosecond timestamp for uniqueness across parallel tests.
	return fmt.Sprintf(`\\.\pipe\acf_test_%d`, time.Now().UnixNano())
}

package transport

import "net"

// Connector abstracts platform-specific IPC listener creation.
//
// On Linux/macOS the implementation uses a Unix Domain Socket.
// On Windows the implementation uses a named pipe.
//
// Everything above the transport layer (frame codec, HMAC, pipeline, policy
// engine) operates on net.Conn — an io.Reader/io.Writer — and is completely
// unaware of which Connector is in use.
type Connector interface {
	// Listen binds to address and returns a net.Listener.
	Listen(address string) (net.Listener, error)

	// DefaultAddress returns the platform-appropriate default address.
	// UDS:   /tmp/acf.sock
	// Pipe:  \\.\pipe\acf
	DefaultAddress() string

	// Cleanup removes any resources left by a previous run.
	// For UDS this removes a stale socket file.
	// For named pipes this is a no-op — pipes have no on-disk residue.
	Cleanup(address string) error
}

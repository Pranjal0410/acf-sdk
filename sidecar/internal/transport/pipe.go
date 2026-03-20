//go:build windows

package transport

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// pipeConnector implements Connector for Windows named pipes.
type pipeConnector struct{}

func (p *pipeConnector) Listen(address string) (net.Listener, error) {
	return winio.ListenPipe(address, &winio.PipeConfig{
		// Byte-stream mode matches the UDS behaviour.
		// The frame codec handles all message framing — pipes do not need
		// message mode.
		MessageMode:     false,
		InputBufferSize: 65536,
		OutputBufferSize: 65536,
	})
}

func (p *pipeConnector) DefaultAddress() string {
	return `\\.\pipe\acf`
}

func (p *pipeConnector) Cleanup(_ string) error {
	// Named pipes leave no on-disk residue — nothing to clean up.
	return nil
}

// DefaultConnector returns the named pipe connector on Windows.
func DefaultConnector() Connector {
	return &pipeConnector{}
}

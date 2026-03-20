// main.go — sidecar entrypoint.
// Phase 1: loads the HMAC key, starts the nonce store, and starts the
// IPC listener (UDS on Linux/macOS, named pipe on Windows).
// Returns a hardcoded ALLOW for every valid request.
// Pipeline stages are wired in Phase 2.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/transport"
)

func main() {
	// 1. Load HMAC key from environment.
	signer, err := crypto.NewSignerFromEnv()
	if err != nil {
		log.Fatalf("sidecar: failed to load HMAC key: %v\n"+
			"  Set ACF_HMAC_KEY to a hex-encoded key (min 32 bytes).\n"+
			"  Generate: python3 -c \"import secrets; print(secrets.token_hex(32))\"", err)
	}

	// 2. Start nonce store with 5-minute TTL.
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	defer nonceStore.Stop()

	// 3. Resolve IPC address (platform-specific default if unset).
	connector := transport.DefaultConnector()
	address := connector.DefaultAddress()
	if p := os.Getenv("ACF_SOCKET_PATH"); p != "" {
		address = p
	}

	// 4. Create and start listener.
	ln, err := transport.NewListener(transport.Config{
		Address:    address,
		Connector:  connector,
		Signer:     signer,
		NonceStore: nonceStore,
	})
	if err != nil {
		log.Fatalf("sidecar: failed to create listener on %s: %v", address, err)
	}

	log.Printf("sidecar: listening on %s (phase 1 — hardcoded ALLOW)", address)

	// 5. Serve in background; block on shutdown signal.
	serveErr := make(chan error, 1)
	go func() { serveErr <- ln.Serve() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		log.Printf("sidecar: received %s, shutting down", sig)
		ln.Stop()
	case err := <-serveErr:
		if err != nil {
			log.Fatalf("sidecar: listener error: %v", err)
		}
	}
}

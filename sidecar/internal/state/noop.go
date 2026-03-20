// noop.go — v1 StateStore implementation.
// Get always returns nil. Set is a no-op.
// Wired in at startup for Phase 1 and Phase 2.
package state

// NoopStore is the v1 StateStore. Stateless — all sessions are equivalent.
type NoopStore struct{}

// Get always returns nil.
func (n *NoopStore) Get(_ string) any { return nil }

// Set is a no-op.
func (n *NoopStore) Set(_ string, _ any) {}

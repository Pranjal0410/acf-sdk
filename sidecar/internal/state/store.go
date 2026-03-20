// Package state defines the StateStore interface and its implementations.
// v1 uses noop.go (stateless). v2 swaps in ttl_store.go at startup injection.
// The pipeline is unchanged between versions — it calls the interface only.
package state

// StateStore is the interface for per-session state hydration.
// v1 uses NoopStore. v2 injects TTLStore at startup — pipeline unchanged.
type StateStore interface {
	// Get returns the stored state for sessionID, or nil if absent.
	Get(sessionID string) any
	// Set stores value for sessionID.
	Set(sessionID string, value any)
}

// aggregate.go — Stage 4 of the pipeline.
// Combines scanner signals into a final risk score (0.0–1.0):
//   - Takes the maximum weight across all emitted signals (avoids score inflation)
//   - Applies provenance trust weight as a multiplier
//   - If State is non-nil (v2), blends in prior_score (placeholder, no-op in v1)
//
// Signal weights come from signal_weights in policies/v1/data/policy_config.yaml,
// supplied by the policy engine and hot-reloaded with the rest of the policy
// data. Provenance trust weights still come from sidecar.yaml.
//
// Writes rc.Score. Does not return hardBlock — score-based blocking is decided
// by the pipeline dispatcher after aggregate completes.
package pipeline

import (
	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// WeightSource supplies the current signal weights: the risk-score
// contribution of each signal category. policy.Engine implements it by reading
// signal_weights from policy_config.yaml on every hot reload.
//
// The returned map is read-only. Implementations replace it wholesale rather
// than mutating it in place.
type WeightSource interface {
	SignalWeights() map[string]float64
}

// StaticWeights is a fixed WeightSource, for tests and for embedders that do
// not run a policy engine.
type StaticWeights map[string]float64

// SignalWeights returns w.
func (w StaticWeights) SignalWeights() map[string]float64 { return w }

// AggregateStage combines signals into a final risk score.
type AggregateStage struct {
	cfg     *config.Config
	weights WeightSource
}

// NewAggregateStage constructs an AggregateStage. cfg supplies the provenance
// trust weights and weights supplies the per-signal weights.
func NewAggregateStage(cfg *config.Config, weights WeightSource) *AggregateStage {
	return &AggregateStage{cfg: cfg, weights: weights}
}

func (a *AggregateStage) Name() string { return "aggregate" }

// Run computes rc.Score from the signals in rc.Signals and back-fills each
// signal's Score field from the current signal weights so OPA sees
// fully-scored signals.
// Always returns hardBlock=false — the dispatcher applies threshold logic.
func (a *AggregateStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	score := applySignalWeights(rc.Signals, a.weights.SignalWeights())
	score *= a.cfg.ProvenanceWeight(rc.Provenance)
	score = clamp(score)

	// v2: blend in historical score from state store (no-op in v1 — State is nil).

	rc.Score = score
	return false
}

// applySignalWeights looks up each signal's weight, writes it back onto the
// signal (so OPA sees sig.score), and returns the maximum weight found.
// Returns 0.0 if no signals are present or none have a configured weight.
//
// A category with no weight contributes nothing, so a detection in an
// unweighted category is silently discarded. The signal-weight contract tests
// (Go and Python) fail when any category the sidecar or the SDK scanner can
// emit is missing from policy_config.yaml.
func applySignalWeights(signals []riskcontext.Signal, weights map[string]float64) float64 {
	var maxW float64
	for i := range signals {
		if w, ok := weights[signals[i].Category]; ok {
			signals[i].Score = w
			if w > maxW {
				maxW = w
			}
		}
	}
	return maxW
}

// clamp ensures score stays within [0.0, 1.0].
func clamp(score float64) float64 {
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

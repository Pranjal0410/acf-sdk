// provenance_forgery_probe_test.go: LOCAL REVIEW PROBE — not part of the suite.
//
// Question: the SDK sets RiskContext.provenance inside the agent process, and
// aggregate.go multiplies the risk score by cfg.ProvenanceWeight(provenance).
// If the agent is compromised — the premise of every injection succeeding —
// the attacker chooses that multiplier. Does claiming a low-trust provenance
// downgrade a verdict the pipeline would otherwise BLOCK?
//
// Reporting only: this test asserts nothing and never fails.
package integration

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// forgeryValues are the provenance strings an attacker could claim. The four
// configured weights come from policy_config.yaml trust_weights; "unknown" is
// included because ProvenanceWeight falls back to 1.0 for unrecognised values.
var forgeryValues = []string{"user_input", "tool_output", "rag_chunk", "memory_read", "not_a_real_provenance"}

func TestProvenanceForgeryProbe(t *testing.T) {
	all := loadCorpus(t)

	// Baseline: the verdict each payload gets with its declared provenance.
	baseline := map[string]string{}
	for _, pc := range all {
		baseline[pc.ID] = send(t, pc)
	}

	var downgrades []string
	weakened := map[string]int{}

	for _, pc := range all {
		base := baseline[pc.ID]
		if base == "ALLOW" {
			continue // nothing to downgrade
		}
		for _, prov := range forgeryValues {
			if prov == pc.Provenance {
				continue
			}
			forged := pc
			forged.Provenance = prov
			got := send(t, forged)
			if got == base {
				continue
			}
			// Only a loosening counts: BLOCK->SANITISE/ALLOW, SANITISE->ALLOW.
			if rank(got) < rank(base) {
				downgrades = append(downgrades, fmt.Sprintf(
					"%s [%s/%s] %s -> %s by claiming provenance=%q (declared %q)",
					pc.ID, pc.HookType, pc.Category, base, got, prov, pc.Provenance))
				weakened[pc.ID]++
			}
		}
	}

	sort.Strings(downgrades)
	var b strings.Builder
	fmt.Fprintf(&b, "\nprovenance forgery probe: %d payloads tested, %d distinct payloads downgraded\n",
		len(all), len(weakened))
	if len(downgrades) == 0 {
		b.WriteString("  no verdict changed under forged provenance\n")
	}
	for _, d := range downgrades {
		fmt.Fprintf(&b, "  %s\n", d)
	}
	t.Log(b.String())
}

// rank orders verdicts by strictness so a drop is detectable.
func rank(d string) int {
	switch d {
	case "BLOCK":
		return 2
	case "SANITISE":
		return 1
	default:
		return 0
	}
}

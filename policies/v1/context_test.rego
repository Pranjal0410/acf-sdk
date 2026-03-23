# ACF-SDK — Context Hook Policy Tests
# Validates: embedded_instruction, structural_anomaly, source_trust,
#            context_risk_threshold, rag_chunk_size_limit

package acf.policy.context_test

import future.keywords.in
import data.acf.policy.context

# =====================================================================
# Detection — structural anomaly → BLOCK
# =====================================================================

test_structural_anomaly_block if {
    result := context.decision with input as {
        "score": 0.3,
        "signals": [{"category": "structural_anomaly", "score": 0.9}],
        "provenance": "rag", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "BLOCK"
}

# =====================================================================
# Detection — embedded instruction → SANITISE
# =====================================================================

test_embedded_instruction_sanitise if {
    result := context.decision with input as {
        "score": 0.2,
        "signals": [{"category": "embedded_instruction", "score": 0.7}],
        "provenance": "rag", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "SANITISE"
}

test_embedded_instruction_targets if {
    targets := context.sanitise_targets with input as {
        "score": 0.2,
        "signals": [{"category": "embedded_instruction", "score": 0.7}],
        "provenance": "rag", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    "context_chunk" in targets
}

test_embedded_instruction_below_threshold_allow if {
    result := context.decision with input as {
        "score": 0.1,
        "signals": [{"category": "embedded_instruction", "score": 0.4}],
        "provenance": "rag", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "ALLOW"
}

# =====================================================================
# Trust — source trust weighting
# =====================================================================

test_low_trust_multiplier if {
    m := context.trust_multiplier with input as {
        "score": 0.3,
        "signals": [{"category": "source_trust", "score": 0.2}],
        "provenance": "external", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    m == 2.0
}

test_high_trust_multiplier if {
    m := context.trust_multiplier with input as {
        "score": 0.3,
        "signals": [{"category": "source_trust", "score": 0.8}],
        "provenance": "internal", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    m == 0.5
}

test_default_trust_multiplier if {
    m := context.trust_multiplier with input as {
        "score": 0.3,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    m == 1.0
}

# Trust amplifies risk: low-trust source pushes score over block threshold
test_low_trust_amplifies_to_block if {
    result := context.decision with input as {
        "score": 0.5,
        "signals": [{"category": "source_trust", "score": 0.1}],
        "provenance": "external", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "BLOCK"
}

# Trust reduces risk: high-trust source keeps score below sanitise threshold
test_high_trust_reduces_to_allow if {
    result := context.decision with input as {
        "score": 0.5,
        "signals": [{"category": "source_trust", "score": 0.8}],
        "provenance": "internal", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "ALLOW"
}

# =====================================================================
# Containment — context risk threshold
# =====================================================================

test_high_score_block if {
    result := context.decision with input as {
        "score": 0.9,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "BLOCK"
}

test_medium_score_sanitise if {
    result := context.decision with input as {
        "score": 0.55,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "SANITISE"
}

test_low_score_allow if {
    result := context.decision with input as {
        "score": 0.2,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 100,
    }
    result == "ALLOW"
}

# =====================================================================
# Containment — RAG chunk size limit → SANITISE (split)
# =====================================================================

test_oversized_chunk_sanitise if {
    result := context.decision with input as {
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 10000,
    }
    result == "SANITISE"
}

test_oversized_chunk_split_target if {
    targets := context.sanitise_targets with input as {
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 10000,
    }
    "split_chunk" in targets
}

test_normal_chunk_allow if {
    result := context.decision with input as {
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_context",
        "payload_size_bytes": 4000,
    }
    result == "ALLOW"
}

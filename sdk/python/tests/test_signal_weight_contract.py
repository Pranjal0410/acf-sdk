"""Every category the SDK semantic scanner can emit must carry a sidecar weight.

The sidecar scores a signal by looking its category up in signal_weights in
policies/v1/data/policy_config.yaml. A category missing from that table scores
0.0 and can never change a verdict, which is how 11 of the scanner's 13
categories went dead without anyone noticing. The Go test
TestPolicyConfig_EveryEmittableSignalHasAWeight covers the lexical library and
the sidecar's own signals; this covers the scanner.

Stdlib-only on purpose, so it runs in CI without the [scanners] extra:
attack_library.py is loaded straight from its file (bypassing the package
__init__, which imports numpy) and the YAML is read with a line parser.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
POLICY_CONFIG = REPO / "policies" / "v1" / "data" / "policy_config.yaml"
ATTACK_LIBRARY = REPO / "sdk" / "python" / "acf" / "scanners" / "attack_library.py"

pytestmark = pytest.mark.skipif(
    not POLICY_CONFIG.exists(),
    reason="policy tree not present (SDK installed without the repo)",
)

# Keys may contain a colon (tool:not_allowed, validate:nil_payload), so match up
# to the colon that is followed by whitespace and a number.
_WEIGHT_LINE = re.compile(r"^\s+([^\s#]\S*?):\s+-?[\d.]")


def weighted_categories() -> set[str]:
    categories: set[str] = set()
    in_table = False
    for line in POLICY_CONFIG.read_text(encoding="utf-8").splitlines():
        if re.match(r"^signal_weights:\s*(#.*)?$", line):
            in_table = True
            continue
        if in_table and line and not line[0].isspace():
            break
        match = _WEIGHT_LINE.match(line) if in_table else None
        if match:
            categories.add(match.group(1))
    return categories


def scanner_categories() -> set[str]:
    spec = importlib.util.spec_from_file_location("_acf_attack_library", ATTACK_LIBRARY)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolves annotations through it
    spec.loader.exec_module(module)
    return {pattern.category for pattern in module.build_pattern_library()}


def test_every_scanner_category_has_a_sidecar_weight():
    weights = weighted_categories()
    assert weights, "parsed no signal_weights from policy_config.yaml"
    missing = sorted(scanner_categories() - weights)
    assert not missing, (
        "semantic scanner categories with no weight in policy_config.yaml — "
        f"the sidecar scores each as 0.0: {missing}"
    )


def test_weight_parser_keeps_namespaced_keys_whole():
    weights = weighted_categories()
    assert "tool:not_allowed" in weights
    assert "validate:nil_payload" in weights
    assert "tool" not in weights

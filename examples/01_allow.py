"""
Example 01 — Clean prompt: ALLOW

A normal user message with no threats. Expected decision: ALLOW.
Score should be 0.0 (no signals fired).
"""

from acf import Firewall, Decision

fw = Firewall()

prompts = [
    "What is the weather in London today?",
    "Summarise the last three paragraphs.",
    "Can you help me write a Python function to sort a list?",
    "Translate this to French: hello world",
]

print("=== 01 — Clean prompts (expect ALLOW) ===\n")

all_passed = True
for prompt in prompts:
    result = fw.on_prompt(prompt)
    status = "PASS" if result == Decision.ALLOW else "FAIL"
    if result != Decision.ALLOW:
        all_passed = False
    print(f"  [{status}] {prompt!r}")
    print(f"         → {result}")

print()
print("PASS — all clean prompts returned ALLOW" if all_passed else "FAIL — unexpected decision")

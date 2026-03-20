# ACF-SDK — Agentic Cognitive Firewall

A Zero Trust security layer for LLM agents. Enforces policy-driven validation at every point an agent ingests input — not just at the front door.

> **Status: active development — Phase 1 (wire protocol) in progress.**

---

## The problem

LLM agents don't have a single input boundary. They ingest from users, RAG pipelines, tool outputs, and memory stores — each a potential attack surface. A single perimeter check at ingress misses everything that arrives later.

ACF-SDK distributes enforcement across the full agent lifecycle:

| Where | Threat |
|---|---|
| User prompt arrives | Direct prompt injection — override system instructions |
| RAG chunks injected | Indirect injection — malicious instructions in retrieved documents |
| Before tool executes | Tool abuse — unsafe tool or malicious parameters |
| Before memory read/write | Memory poisoning — malicious values in persistent agent state |

---

## How it works

![ACF-SDK architecture](docs/architecture.png)

Two zones separated by a hard OS process boundary:

- **PEP** — a thin SDK inside your agent process. Signs payloads and dispatches over IPC.
- **PDP** — an isolated Go sidecar. All policy evaluation happens here. The agent cannot reach inside it.

The sidecar runs every payload through a four-stage pipeline — validate, normalise, scan, aggregate — then evaluates OPA (Rego) policies to produce a structured decision.

Every decision is one of three outcomes:

| Decision | Meaning |
|---|---|
| `ALLOW` | Payload is clean — pass through |
| `SANITISE` | Payload contains a threat — return scrubbed version with warning markers |
| `BLOCK` | Hard block — agent must not proceed with this input |

Enforcement latency: **4–8ms typical, ~10ms worst case.** Observability spans emit asynchronously and never touch the enforcement path.

---

<!-- ## Quick start (Python)

```python
from acf import Firewall, Decision

firewall = Firewall()  # connects to sidecar at /tmp/acf.sock

# At message ingress
result = firewall.on_prompt(user_message)
if result.decision == Decision.BLOCK:
    raise ValueError("Input blocked by firewall")
if result.decision == Decision.SANITISE:
    user_message = result.sanitised  # use scrubbed version

# Before RAG injection
chunks = firewall.on_context(retrieved_docs)
safe_chunks = [c.sanitised for c in chunks if c.decision != Decision.BLOCK]

# Before tool execution
result = firewall.on_tool_call(tool_name, tool_params)
if result.decision == Decision.BLOCK:
    raise ToolException("Tool call blocked by firewall")

# Before memory write
result = firewall.on_memory(key, value, op="write")
if result.decision != Decision.ALLOW:
    raise MemoryException("Memory write blocked by firewall")
```

### LangGraph adapter

```python
from acf.adapters.langgraph import FirewallNode
from langgraph.graph import StateGraph

graph = StateGraph(AgentState)
graph.add_node("firewall", FirewallNode(firewall))
graph.add_node("agent", your_agent_node)
graph.add_edge("firewall", "agent")
``` -->

---

## Architecture

### Seam 1 — Hook registry

![Hook registry](docs/hook-registry.png)

Hooks self-register at startup. The pipeline only calls whatever is registered. Adding a new hook (v2: `on_tool_result`, `on_outbound`, `on_subagent`) is purely additive — the pipeline, IPC layer, and sidecar core do not change.

### Seam 2 — Risk context object

![Risk context object](docs/risk_context_object.png)

A single typed payload flows through every pipeline stage. The schema is fixed across v1 and v2 — the `state` field is null in v1 and populated by a TTL session store in v2. Policy files work unchanged across both versions.

### Sidecar pipeline

```
validate → normalise → scan → aggregate → OPA policy engine → executor
```

| Stage | What it does |
|---|---|
| **Validate** | HMAC verify, nonce replay check, schema validation |
| **Normalise** | URL/Base64/hex decode, NFKC unicode, zero-width strip, leetspeak clean |
| **Scan** | Aho-Corasick lexical scan, allowlist checks, integrity verification |
| **Aggregate** | Combines signals into risk score 0.0–1.0 with provenance trust weighting |
| **Policy engine** | OPA (Rego) evaluates rules per hook type, returns structured decision |
| **Executor** | Performs string transforms declared by OPA on SANITISE decisions |

Short-circuits to BLOCK at any stage on a hard signal.

---

## Policies

Policies are Rego files, hot-reloadable without restarting the sidecar. Logic and data are kept separate so pattern library updates never require touching decision rules.

```
policies/v1/
├── prompt.rego          instruction override · role escalation · jailbreak
├── context.rego         source trust · embedded instruction · structural anomaly
├── tool.rego            allowlist · shell metachar · path traversal · network
├── memory.rego          HMAC stamp/verify · write scan · provenance
└── data/
    ├── policy_config.yaml         thresholds · allowlists · trust weights
    └── jailbreak_patterns.json    versioned pattern library
```

Test policies with `make opa-test` — runs the full Rego test suite using `opa test`.

---

<!-- ## Getting started

### Prerequisites

- Go 1.22+
- Python 3.10+
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) (for policy tests)

### Build the sidecar

```bash
make build
# → bin/acf-sidecar
```

### Configure

```bash
cp config/sidecar.example.yaml config/sidecar.yaml
export ACF_HMAC_KEY=$(python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")
```

### Run

```bash
./bin/acf-sidecar --config config/sidecar.yaml
```

### Install the Python SDK

```bash
pip install -e sdk/python
```

### Run tests

```bash
make test            # Go unit tests
make opa-test        # Rego policy tests
make sdk-test-python # Python SDK tests
make integration     # End-to-end adversarial test suite (requires running sidecar)
```

### Docker (sidecar + OTel collector)

```bash
docker compose up -d

# With observability:
docker compose --profile observability up -d
``` -->

---

## Project structure

```
acf-sdk/
├── sidecar/              Go enforcement kernel (PDP)
├── sdk/
│   ├── python/           Python SDK v1 — zero external dependencies
│   └── typescript/       TypeScript SDK v2 — deferred until v1 is stable
├── policies/v1/          Rego policies + data
├── tests/integration/    33-payload adversarial test suite
├── config/               Sidecar configuration
└── docs/                 Architecture and policy authoring guides
```

---

## Roadmap

| Phase | Goal | Status |
|---|---|---|
| 1 | Wire protocol + HMAC/nonce crypto | In progress |
| 2 | Pipeline stages (validate/normalise/scan/aggregate) | Pending |
| 3 | OPA integration + Rego policies | Pending |
| 4 | OTel observability + integration test suite | Pending |
| v2 | Stateful session risk, additional hooks, TypeScript SDK | Deferred |

---

## Design principles

See [PHILOSOPHY.md](PHILOSOPHY.md) for the full design rationale. The short version:

- **Zero Trust** — all inputs are untrusted by default, regardless of source
- **Policy-as-code** — Rego rules are version-controlled, auditable, and hot-reloadable
- **Minimal overhead** — 4–8ms enforcement adds no meaningful latency to agent workflows
- **Additive by design** — new hooks, policy versions, and SDK languages never require changing existing components
- **Framework-agnostic** — works with LangGraph, LangChain, or any custom agent loop

---

## Documentation

- [Architecture](docs/architecture.md) — full system design, IPC wire protocol, pipeline stages
- [Policy authoring](docs/policy-authoring.md) — how to write and test Rego policies
- [Philosophy](PHILOSOPHY.md) — design principles and threat model rationale

---

## License

See [LICENSE](LICENSE).

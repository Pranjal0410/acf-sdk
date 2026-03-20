# Phase 1 — Wire Protocol & Crypto

**Goal:** The Python SDK can send a cryptographically signed frame to the Go sidecar over IPC. The sidecar verifies the HMAC and nonce, and returns a hardcoded ALLOW response. No pipeline logic runs yet — that is Phase 2.

**Status: complete.** 23 Go tests, 35 Python tests — all passing. `go vet` clean. Runs on Linux, macOS, and Windows.

---

## What was built

### Go sidecar

#### `pkg/riskcontext/context.go`
Defines `RiskContext` — the single typed struct that flows through every pipeline stage. Fixed schema across v1 and v2: `score`, `signals`, `provenance`, `session_id`, `hook_type`, `payload`, `state`. The `state` field is `nil` in v1; the policy engine checks for non-nil before including session history.

#### `internal/crypto/hmac.go`
`Signer` wraps an HMAC-SHA256 key with two methods:
- `Sign(msg []byte) []byte` — returns a 32-byte MAC
- `Verify(msg, mac []byte) bool` — constant-time comparison via `hmac.Equal` (prevents timing attacks)

Key is loaded from the `ACF_HMAC_KEY` environment variable (hex-encoded) via `NewSignerFromEnv()`.

#### `internal/crypto/nonce.go`
`NonceStore` tracks seen nonces in a `map[string]time.Time` protected by a mutex. `Seen(nonce)` is atomic — the check and record happen under the same lock to prevent TOCTOU races. A background goroutine evicts expired entries every TTL interval. Default TTL: 5 minutes.

#### `internal/state/store.go` + `noop.go`
`StateStore` interface with `Get(sessionID) any` and `Set(sessionID, value)`. `NoopStore` is the v1 implementation — `Get` always returns nil, `Set` is a no-op. v2 will inject `TTLStore` at startup without touching the pipeline.

#### `internal/transport/frame.go`
Encodes and decodes the binary IPC protocol. The 54-byte request header layout:

```
[0]      magic     0xAC
[1]      version   0x01
[2:6]    length    uint32 big-endian — payload length
[6:22]   nonce     16 random bytes — per-request
[22:54]  HMAC      32 bytes — HMAC-SHA256 over SignedMessage(version+length+nonce+payload)
[54:]    payload   JSON-serialised RiskContext
```

Response frame:
```
[0]      decision  0x00 ALLOW · 0x01 SANITISE · 0x02 BLOCK
[1:5]    san_len   uint32 big-endian (0 if not SANITISE)
[5:]     sanitised JSON bytes (SANITISE only)
```

`SignedMessage()` is a separate function used by both encoder and verifier to guarantee they sign and verify the same byte sequence.

Sentinel errors: `ErrBadMagic`, `ErrBadVersion`, `ErrBadHMAC`, `ErrReplayNonce`.

#### `internal/transport/connector.go`
`Connector` interface abstracts the platform IPC mechanism:
```go
type Connector interface {
    Listen(address string) (net.Listener, error)
    DefaultAddress() string
    Cleanup(address string) error
}
```
`DefaultConnector()` returns the correct implementation for the current OS at compile time via build tags.

#### `internal/transport/uds.go` (Linux/macOS, `!windows`)
`udsConnector` — binds a Unix Domain Socket, cleans up stale socket files before binding, default address `/tmp/acf.sock`.

#### `internal/transport/pipe.go` (Windows, `windows`)
`pipeConnector` — binds a Windows named pipe via `github.com/Microsoft/go-winio`, default address `\\.\pipe\acf`. Named pipes leave no on-disk residue — no cleanup needed.

#### `internal/transport/listener.go`
IPC accept loop. Uses `cfg.Connector` for all platform operations. Per-connection handler (`handleConn`):
1. Decode frame — drop on `ErrBadMagic` or `ErrBadVersion`
2. Verify HMAC — drop on failure (no response written)
3. Check nonce replay — drop on replay (no response written)
4. Write hardcoded ALLOW response (`0x00 + 4 zero bytes`)

`Stop()` closes the listener cleanly; `Serve()` returns `nil` after a clean shutdown.

#### `cmd/sidecar/main.go`
Entrypoint wiring for Phase 1 — no YAML config yet:
- `ACF_HMAC_KEY` (required) — hex-encoded HMAC key
- `ACF_SOCKET_PATH` (optional) — overrides the platform default IPC address

Handles `SIGTERM` and `SIGINT` for clean shutdown.

---

### Python SDK

#### `acf/models.py`
- `Decision` enum: `ALLOW = 0x00`, `SANITISE = 0x01`, `BLOCK = 0x02`, with `from_byte(b)` factory
- `SanitiseResult` dataclass: `decision`, `sanitised_payload` (bytes), `sanitised_text` (str or None)
- `ChunkResult` dataclass: `original`, `decision`, `sanitised_text`
- `FirewallError` / `FirewallConnectionError` exception hierarchy

#### `acf/frame.py`
Pure encoding logic, no I/O. Mirrors `frame.go` byte-for-byte:
- `encode_request(payload, key)` — generates nonce via `secrets.token_bytes(16)`, computes HMAC with `hmac.new(key, msg, hashlib.sha256).digest()`, packs with `struct.pack(">BB I 16s 32s", ...)`
- `decode_request(data)` — validates magic and version, returns dict
- `encode_response(decision, sanitised)` / `decode_response(data)`
- `signed_message(version, length, nonce, payload)` — identical composition to Go's `SignedMessage()`

#### `acf/transport.py`
`Transport` — one new IPC connection per request (connection-per-request, pooling deferred). Platform-aware: auto-detects Windows vs Linux/macOS at runtime.

- **Linux/macOS:** Unix Domain Socket via `socket.AF_UNIX`
- **Windows:** Named pipe via `ctypes` Win32 API (`CreateFile` / `WriteFile` / `ReadFile`) — zero external dependencies
- Retries on `ConnectionRefusedError` / `FileNotFoundError` with exponential backoff (0.1s, 0.2s, 0.4s), max 3 attempts
- Other `OSError` subclasses re-raised immediately (no retry)
- Raises `FirewallConnectionError` after exhausting retries
- `DEFAULT_SOCKET_PATH` resolves to `\\.\pipe\acf` on Windows, `/tmp/acf.sock` elsewhere

#### `acf/firewall.py`
`Firewall` — the developer-facing class:

```python
firewall = Firewall()  # reads ACF_HMAC_KEY from env

firewall.on_prompt(text)              # → Decision | SanitiseResult
firewall.on_context(chunks)           # → list[ChunkResult]
firewall.on_tool_call(name, params)   # → Decision | SanitiseResult
firewall.on_memory(key, value, op)    # → Decision | SanitiseResult
```

Each method builds the `RiskContext` JSON payload, sends it via `Transport`, and decodes the response. The HMAC key is resolved from the `hmac_key` constructor argument or the `ACF_HMAC_KEY` environment variable.

---

## Test coverage

### Go (23 tests)

| Package | Tests |
|---|---|
| `internal/crypto` | Sign determinism · different keys produce different MACs · Verify valid MAC · Verify corrupted MAC · Verify corrupted message · NewSigner empty key · NewSignerFromEnv valid/missing/invalid |
| `internal/crypto` | NonceStore first use · replay · different nonces · expiry after TTL · 100-goroutine concurrent access |
| `internal/transport` | EncodeRequest header fields · nonce uniqueness · decode round-trip · bad magic · bad version · truncated frame · EncodeResponse ALLOW · EncodeResponse SANITISE · DecodeResponse all three decisions · SignedMessage byte composition |
| `internal/transport` | Listener round-trip (real named pipe) · bad HMAC (connection dropped) · nonce replay (connection dropped) · bad magic (connection dropped) · Stop() cleanly terminates Serve() |

### Python (35 tests)

| Module | Tests |
|---|---|
| `test_frame` | Magic byte · version byte · length field · nonce length · nonce uniqueness · total frame length · HMAC validity · decode round-trip · bad magic · bad version · truncated header · truncated payload · decode response ALLOW/BLOCK/SANITISE · truncated response · signed_message composition |
| `test_models` | Decision members and values · from_byte ALLOW/SANITISE/BLOCK · from_byte invalid · SanitiseResult fields · ChunkResult fields · FirewallError hierarchy |
| `test_transport` | ALLOW/BLOCK/SANITISE response decoding · retry on ConnectionRefusedError (2 failures then success) · retry exhausted → FirewallConnectionError · non-transient error not retried · HMAC verified in sent frame |

---

## Running Phase 1

### Prerequisites
- Go 1.22+
- Python 3.10+

### Build and run the sidecar

**Linux/macOS:**
```bash
export ACF_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
cd sidecar && go build -o ../bin/acf-sidecar ./cmd/sidecar
./bin/acf-sidecar
# sidecar: listening on /tmp/acf.sock (phase 1 — hardcoded ALLOW)
```

**Windows (PowerShell):**
```powershell
$env:ACF_HMAC_KEY = python -c "import secrets; print(secrets.token_hex(32))"
cd sidecar; go build -o ..\bin\acf-sidecar.exe .\cmd\sidecar
..\bin\acf-sidecar.exe
# sidecar: listening on \\.\pipe\acf (phase 1 — hardcoded ALLOW)
```

### Install and smoke-test the Python SDK

```bash
pip install -e sdk/python

python3 - <<'EOF'
import os
from acf import Firewall, Decision

fw = Firewall()  # reads ACF_HMAC_KEY from env
result = fw.on_prompt("hello world")
assert result == Decision.ALLOW, f"Expected ALLOW, got {result}"
print("PASS: round-trip ALLOW")
EOF
```

### Run the test suites

```bash
# Go
cd sidecar && go test ./internal/crypto/... ./internal/transport/... -v

# Python
cd sdk/python && python -m pytest -v
```

---

## What Phase 1 does NOT do

- No pipeline stages (validate/normalise/scan/aggregate) — every valid frame returns ALLOW
- No OPA policy evaluation
- No YAML config file parsing — two environment variables only
- No OTel spans
- No TypeScript SDK

All of the above are explicitly deferred to Phases 2–4 to keep the scope bounded and the deliverable verifiable.

---

## Phase 2 preview

Phase 2 wires the four pipeline stages into `handleConn` in `listener.go`. The only file that changes at the integration point is the listener — the frame codec, crypto, nonce store, and Connector abstraction are untouched.

Files to implement in Phase 2:
- `internal/pipeline/pipeline.go` — orchestrator, short-circuit on hard block
- `internal/pipeline/validate.go` — schema validation (HMAC already done in listener)
- `internal/pipeline/normalise.go` — URL/Base64/hex decode, NFKC, zero-width, leetspeak
- `internal/pipeline/scan.go` — Aho-Corasick against `jailbreak_patterns.json`, allowlist checks
- `internal/pipeline/aggregate.go` — risk score, provenance trust weight
- `internal/state/noop.go` wired into the pipeline as the `StateStore`

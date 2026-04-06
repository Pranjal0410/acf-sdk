# ACF-SDK Examples

Manual test scripts for verifying Phase 2 pipeline behaviour end-to-end.
Each script requires the sidecar to be running locally.

## Setup (run once)

### Step 1 — Generate the HMAC key

Run this **once** to generate a key and copy the output:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# e.g. 3f8a2bd91c4e...
```

You will set this value in **both** terminals below. The sidecar and the SDK must share the identical key — the sidecar uses it to verify every frame, the SDK uses it to sign every frame before sending.

---

### Step 2 — Terminal 1: set key and start the sidecar

**Linux / macOS:**
```bash
export ACF_HMAC_KEY="<paste key here>"
cd sidecar && go run ./cmd/sidecar
# sidecar: pipeline ready (mode=strict, block_threshold=0.85)
# sidecar: listening on /tmp/acf.sock
```

**Windows (PowerShell):**
```powershell
$env:ACF_HMAC_KEY = "<paste key here>"
cd sidecar; go run .\cmd\sidecar
# sidecar: pipeline ready (mode=strict, block_threshold=0.85)
# sidecar: listening on \\.\pipe\acf
```

**Windows (cmd.exe):**
```cmd
set ACF_HMAC_KEY=<paste key here>
cd sidecar && go run .\cmd\sidecar
```

> Run from the **`sidecar/` directory** — the Go module root. Config and policies are resolved automatically from `../config/` and `../policies/`.

Keep this terminal open and the sidecar running.

---

### Step 3 — Terminal 2: set the same key and run examples

Open a **new terminal** and set the **same key** again — environment variables are not shared between terminals:

**Linux / macOS:**
```bash
export ACF_HMAC_KEY="<paste same key here>"
```

**Windows (PowerShell):**
```powershell
$env:ACF_HMAC_KEY = "<paste same key here>"
```

**Windows (cmd.exe):**
```cmd
set ACF_HMAC_KEY=<paste same key here>
```

Then install the Python SDK (only needed once):

```bash
pip install -e sdk/python
```

> **Tip:** To avoid setting the key in every new terminal, add it to your shell profile (`~/.bashrc`, `~/.zshrc`) or Windows user environment variables via `sysdm.cpl` → Advanced → Environment Variables.

---

### Step 4 — Run the examples

From the **repo root** in terminal 2:

**Linux / macOS:**
```bash
cd sidecar && go run ./cmd/sidecar
# sidecar: pipeline ready (mode=strict, block_threshold=0.85)
# sidecar: listening on /tmp/acf.sock
```

**Windows (PowerShell):**
```powershell
cd sidecar; go run .\cmd\sidecar
# sidecar: pipeline ready (mode=strict, block_threshold=0.85)
# sidecar: listening on \\.\pipe\acf
```

> Run from the **`sidecar/` directory** — the Go module root. The sidecar automatically resolves `../config/sidecar.yaml` and `../policies/v1` relative to that location. Override with `ACF_CONFIG` env var if needed.


**Linux / macOS:**
```bash
python3 examples/01_allow.py            # clean prompt  → ALLOW
python3 examples/02_block_jailbreak.py  # jailbreak → BLOCK
python3 examples/03_block_tool.py       # unknown tool → BLOCK
python3 examples/04_rag_sanitise.py     # poisoned RAG → SANITISE
python3 examples/05_evasion.py          # evasion attempts → BLOCK
python3 examples/06_non_strict.py       # non-strict mode audit demo
python3 examples/07_all_hooks.py        # all four hook types
```

**Windows (PowerShell):**
```powershell
python examples/01_allow.py
python examples/02_block_jailbreak.py
python examples/03_block_tool.py
python examples/04_rag_sanitise.py
python examples/05_evasion.py
python examples/06_non_strict.py
python examples/07_all_hooks.py
```

Run all at once:

**Linux / macOS:**
```bash
for f in examples/0*.py; do echo "--- $f ---"; python3 "$f"; done
```

**Windows (PowerShell):**
```powershell
Get-ChildItem examples\0*.py | ForEach-Object { Write-Host "--- $_ ---"; python $_ }
```

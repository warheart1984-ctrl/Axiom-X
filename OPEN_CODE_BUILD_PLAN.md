# OpenCode Build Plan — Axiom-X Governed Workloads v0.1

## Mission

Implement the first end-to-end governed workload in Axiom-X: `kokoro.chapter1`.
The workload must accept text, select an execution backend, render WAV audio,
and emit a truthful JSON receipt. The architecture must support future Vulkan,
DITB, language-model, image, music, and simulation workloads without claiming
hardware capabilities that have not passed tests.

## Non-negotiable engineering rules

1. Preserve the existing Axiom-X microkernel design and constitutional contracts.
2. Do not modify governance documents to make tests pass.
3. Do not claim Vulkan, ROCm, RX 580, resource enforcement, or deterministic replay
   until a real test proves each capability.
4. Keep the host-testable path independent from freestanding kernel assembly.
5. Every execution decision must produce a structured evidence record.
6. CPU Kokoro remains the safe fallback throughout development.
7. Never upload source text or generated audio to a cloud service.

## Target repository

`/media/jon/New Volume/Project Finish/Sovereign-X-Constitutional-Compute/axiom-x`

The workspace contains Axiom-X Rust crates, including `axiom-x-math`,
`axiom-x-arch`, `axiom-x-boot`, `axiom-x-kernel`, and `axiom-x-sys`.

## Phase 0 — Baseline and inventory

Run and record:

```bash
cargo test
cargo check --workspace
git status --short
```

Inspect existing authority, continuity, evidence, scheduler, and arena code.
Do not overwrite unrelated user changes. Create a feature branch named
`codex/axiom-x-governed-workloads` unless the operator supplies another branch.

Acceptance gate: baseline commands and existing tests pass, or failures are
recorded before implementation.

## Phase 1 — Application contract types

Add a host-testable crate or module named `axiom-x-app-contract` containing:

- `ApplicationContract`
- `ResourceDeclaration`
- `BackendPreferences`
- `EvidenceRequirements`
- `IoContract`
- `ExecutionPolicy`
- `WorkloadRequest`

Use enums for workload type, backend, precision, evidence level, receipt format,
replay mode, and determinism mode. Validate:

- non-empty `app_id`, semantic version, and intent
- non-zero memory when required
- compatible input/output formats
- fallback backend is different from preferred backend when both exist
- `ditb_required` is explicit
- audit tags are non-empty and bounded

Return structured validation errors; never panic on malformed application input.

Add serialization tests and invalid-contract tests.

## Phase 2 — Scheduler decision and authority scope

Extend the existing scheduler/authority flow with a host-testable decision API:

```text
submit(contract, input_metadata) -> SchedulingDecision
```

The decision must include:

- authority scope
- selected backend
- fallback availability
- resource grant
- contract hash
- intent text
- parent continuity identifier
- evidence level

For v0.1, backend selection rules are:

1. Select Vulkan only when an explicit probe reports it as available and verified.
2. Otherwise select CPU.
3. Never report Vulkan merely because a Vulkan library or GPU is installed.
4. If `ditb_required` is true and DITB is unavailable, return a structured refusal.

Add deterministic unit tests for CPU selection, Vulkan refusal, fallback, and
authority scope generation.

## Phase 3 — Evidence and receipt format

Define a versioned JSON receipt schema:

```json
{
  "schema_version": "axiom-x-receipt-0.1",
  "app_id": "kokoro.chapter1",
  "contract_hash": "sha256:...",
  "intent": "Render Chapter-1 text into WAV audio",
  "authority_scope": "authority:audio.render.chapter1",
  "backend_requested": "Vulkan",
  "backend_selected": "CPU",
  "backend_verified": false,
  "fallback_used": true,
  "input_sha256": "sha256:...",
  "output_sha256": "sha256:...",
  "duration_ms": 0,
  "determinism_mode": "best-effort",
  "replay_surface": "required",
  "audit_tags": ["kokoro", "chapter1", "audio.render"],
  "status": "completed",
  "errors": [],
  "evidence": []
}
```

Hash bytes, not paths. Redact source text from receipts. Write the receipt only
after output validation. On failure, write a receipt with `status: failed` and
structured error codes.

Add tests for stable contract hashes, output hashes, failure receipts, and JSON
round trips.

## Phase 4 — Kokoro CPU adapter

Implement an external-process adapter, not kernel-space TTS code. The adapter
must accept a text file and output a WAV file through the existing local CPU
Kokoro server or configured local helper.

Required behavior:

- bounded text size and chunk count
- timeout and cancellation
- no network access
- explicit voice and sample-rate metadata
- existing WAV validation
- resumable chunk receipts
- FFmpeg MP3 export may remain outside Axiom-X v0.1

Use the existing working CPU Kokoro path as the reference implementation.
Record `backend_selected: CPU`, `backend_verified: true`, and
`fallback_used: true` when CPU is selected because Vulkan is unavailable.

Add a short fixture test that produces a non-empty WAV and validates duration,
sample rate, channels, and hash.

## Phase 5 — Vulkan capability probe

Add a read-only probe executable/module that reports:

- Vulkan loader availability
- physical device name/vendor
- API version
- queue-family availability
- required compute features
- supported precision paths
- probe status: `available`, `unsupported`, or `error`

Do not call this a Kokoro backend yet. Add a minimal compute proof using one
buffer operation and compare its output with a CPU reference. Store the proof as
a separate evidence record.

Acceptance gate: a Vulkan device probe is not sufficient. The buffer operation
must execute and match the CPU result within a declared tolerance.

## Phase 6 — Narrow Vulkan tensor backend

Only after Phase 5 passes, implement the smallest operator set needed by a model
fixture:

1. buffer upload/download
2. matrix multiplication
3. elementwise activation
4. convolution or the next operator demonstrated as required
5. synchronization and error propagation

Keep the backend behind a trait:

```rust
trait ComputeBackend {
    fn name(&self) -> &'static str;
    fn probe(&self) -> BackendProbe;
    fn execute(&self, request: &ComputeRequest) -> Result<ComputeResult, ComputeError>;
}
```

Do not claim Kokoro acceleration until the complete Kokoro fixture renders a
valid WAV and passes CPU comparison checks.

## Phase 7 — DITB integration boundary

Treat DITB as an optional CPU compatibility layer only. It may launch a helper
process when a workload explicitly requires legacy instruction translation.
It must not be described as a ROCm-to-Vulkan translator.

Record DITB version, translated instruction count when available, exit status,
and whether the workload actually used the translated process.

Add an integration test using a harmless helper binary before connecting it to
Kokoro.

## Phase 8 — Kokoro Chapter-1 workload

Add a checked-in example contract at `examples/kokoro_chapter1.json`:

- `app_id`: `kokoro.chapter1`
- `version`: `0.1.0`
- `workload_type`: `audio_synthesis`
- preferred backend: `Vulkan`
- fallback backend: `CPU`
- precision: `fp32`
- evidence level: `standard`
- receipt format: `JSON`
- replay surface: required
- determinism: `hybrid` until replay is proven
- audit tags: `kokoro`, `chapter1`, `audio.render`

Add a CLI command:

```text
axiom-x-run --contract examples/kokoro_chapter1.json \
  --input chapter1.txt --output chapter1.wav --receipt chapter1.receipt.json
```

The CLI must print a short human-readable result while keeping detailed data in
the receipt.

## Phase 9 — Replay and audit validation

Implement replay metadata first, then replay execution. A replay is valid only
when the selected backend, model/voice metadata, input hash, output properties,
and declared tolerance all match.

For CPU Kokoro, classify waveform equality honestly. If exact samples are not
stable, use `best-effort` and compare duration plus a declared signal tolerance.

Acceptance artifacts:

- WAV output
- JSON receipt
- replay result
- audit log entry
- refusal receipt for an unavailable Vulkan request

## Required final verification

Run:

```bash
cargo fmt --all -- --check
cargo test
cargo check --workspace
```

If a freestanding target is available, also run the documented kernel-target
check. Do not imply that host tests prove hardware boot or GPU execution.

## Definition of done

The build is complete when:

1. Axiom-X validates the application contract.
2. It issues a scoped authority decision.
3. It selects CPU safely when Vulkan is not verified.
4. `kokoro.chapter1` produces a real WAV through the local CPU adapter.
5. A JSON receipt contains hashes, backend decision, evidence, and errors.
6. Replay behavior is tested and honestly classified.
7. Vulkan remains marked unavailable or experimental unless its complete proof passes.
8. Existing Axiom-X tests still pass.

## Handoff report format

OpenCode must finish by reporting:

- files changed
- commands run and results
- exact workload output paths
- selected and verified backend
- receipt path
- replay result
- known limitations
- commit hash

Never replace a failed hardware or replay gate with a documentation-only claim.

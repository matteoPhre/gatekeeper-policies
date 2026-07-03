# Roadmap

This roadmap is the merged canonical plan for the repository. It combines the architectural priorities from the previous roadmap drafts and uses one file to track both completed work and remaining gaps.

Legend:
- `[x]` implemented in the current codebase
- `[ ]` not yet implemented

## Phase 0 - Core Architecture Hardening

1. [x] Introduce unified PolicyDecision model across the core modules.
2. [x] Replace all boolean returns with typed decision objects.
3. [x] Introduce strict error code unions.
4. [x] Split IdentityPolicyEngine into the focused engines already present in `src/policy-core.ts`.
5. [x] Introduce trace/debug evaluation support with opt-in zero-overhead tracing.
6. [x] Normalize async model across all public APIs.
	- Decide whether sync methods (e.g. `validateComplexity`) stay sync by design or move to a consistent sync/async split, and document the rationale explicitly.
7. [x] Add fail-open / fail-closed strategy configuration.
8. [x] Enforce deep immutable configuration at runtime.
9. [x] Define a formal deprecation path for boolean compatibility wrappers:
	- `@deprecated` JSDoc annotations.
	- optional runtime warning (opt-in, non-breaking).
	- target version for removal.

Current gap:
- boolean compatibility wrappers still exist for host code that depends on them, but the typed decision methods are now the canonical API across the engine and adapter layer.

## Phase 1 - Quality Gates

1. [x] Add property-based testing for complexity validation, rotation logic, and expiry lifecycle.
2. [x] Add contract tests for extension interfaces and external comparators.
3. [x] Add determinism verification tests for same input -> same output.
4. [x] Add CI matrix for multiple Node.js LTS versions.
5. [x] Add a benchmark suite with regression thresholds, so performance stability is tracked across releases in the same way correctness is.
6. [x] Add targeted fuzzing for `constantTimeEqual` / `constantTimeStringEqual` to catch accidental timing-safety regressions introduced by future refactors.

## Phase 2 - Policy Hardening

1. [x] Add configurable lower-case requirement (`requireLowercase`).
2. [x] Add configurable maximum length (`maxLength`).
3. [x] Add configurable deny-lists.
4. [x] Add repeated/sequential character detection rules.
5. [x] Add deterministic normalization pipeline:
	- trim first
	- unicode normalization second
	- metric evaluation last

## Phase 3 - Rotation and Reuse Controls

1. [x] Enforce minimum password age before change.
2. [x] Extend history comparison strategy interface.
3. [x] Add bulk-history comparison helper.
4. [x] Add optional substring blocking from previous secrets.

## Phase 4 - Expiry Lifecycle

1. [x] Add warning window calculation (`daysUntilExpiry`).
2. [x] Add grace period helpers.
3. [x] Add explicit lifecycle states:
	- valid
	- warning
	- grace
	- expired
4. [x] Keep UTC-safe calendar utilities.

## Phase 5 - Audit and Observability

1. [x] Introduce strongly typed audit event schema:
	- complexity
	- rotation
	- expiry
	- minimumPasswordAge
	- gracePeriod
2. [x] Ensure audit includes:
	- policyVersion
	- timestamp
	- outcome
	- structured metadata
3. [x] Keep audit callback non-blocking and failure-isolated.
4. [x] Define an explicit redaction/PII policy for audit payloads, guaranteeing plaintext passwords can never leak into audit events, including from unhandled exceptions inside custom hooks.
5. [x] Introduce schema versioning for audit events themselves (distinct from `policyVersion`), so downstream consumers can handle breaking changes to the event shape.

## Phase 6 - Extension Isolation

Move to a future external package:

- entropy validators (zxcvbn-like)
- compromised password checks
- k-anonymity integrations

Core must remain:
- deterministic
- dependency-free
- predictable

Status:
- [ ] still bundled in the core surface today; this is the main intentional gap before extraction.
- [x] Define the extension interface contracts (`EntropyValidator`, `CompromisedPasswordChecker`) ahead of extraction, so the future external package can be a drop-in without requiring a breaking change in core.

## Phase 7 - Adapter Ecosystem

1. [x] Provide minimal adapter examples:
	- Express
	- Fastify
	- custom runtime
2. [x] Avoid framework coupling in core.

## Phase 8 - Cross-Language Interoperability

1. [x] Export a JSON Schema (or OpenAPI-style) representation of the `PolicyDecision` types, so non-TypeScript consumers (e.g. services in other languages) can validate against the same contract.

## Phase 9 - Rate Limiting / Lockout Policies

1. [x] Add support for tracking consecutive failed attempts.
2. [x] Add configurable temporary lockout policy decisions, following the same typed-decision model used elsewhere in the engine.

## Phase 10 - Advanced Observability

1. [x] Add an optional metrics hook (counters/histograms) alongside the existing audit event, exposing a minimal interface compatible with common observability conventions (e.g. OpenTelemetry-shaped) without adding a hard dependency, consistent with the dependency-free core philosophy.

## Compatibility Commitment

The following must always hold:

1. Framework agnosticism in core modules.
2. No mandatory database or ORM dependencies.
3. Deterministic execution for core policy evaluation.
4. Strong typing across all public APIs.

## Notes On Remaining Work

The remaining highest-priority work is:

1. Keep the typed decision methods as the primary API and trim any remaining documentation references that suggest boolean helpers are the preferred path.
2. Plan the phase-6 extraction of entropy and compromised-password checks into a future external package.
3. Update playground examples to prioritize typed decision APIs and lockout/metrics hooks.
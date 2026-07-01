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
6. [ ] Normalize async model across all public APIs.
7. [x] Add fail-open / fail-closed strategy configuration.
8. [x] Enforce deep immutable configuration at runtime.

Current gap:
- boolean compatibility wrappers still exist for host code that depends on them, but the typed decision methods are now the canonical API across the engine and adapter layer.

## Phase 1 - Quality Gates

1. [x] Add property-based testing for complexity validation, rotation logic, and expiry lifecycle.
2. [x] Add contract tests for extension interfaces and external comparators.
3. [x] Add determinism verification tests for same input -> same output.
4. [ ] Add CI matrix for multiple Node.js LTS versions.

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

## Phase 7 - Adapter Ecosystem

1. [x] Provide minimal adapter examples:
	- Express
	- Fastify
	- custom runtime
2. [x] Avoid framework coupling in core.

## Compatibility Commitment

The following must always hold:

1. Framework agnosticism in core modules.
2. No mandatory database or ORM dependencies.
3. Deterministic execution for core policy evaluation.
4. Strong typing across all public APIs.

## Notes On Remaining Work

The remaining highest-priority work is:

1. Keep the typed decision methods as the primary API and trim any remaining documentation references that suggest boolean helpers are the preferred path.
2. Add the CI matrix for multiple Node.js LTS versions.
3. Plan the phase-6 extraction of entropy and compromised-password checks into a future external package.

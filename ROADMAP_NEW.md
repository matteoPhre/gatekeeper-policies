# Roadmap

This roadmap prioritizes architectural stability and adoption-readiness before feature expansion.

---

## Phase 0 - Core Architecture Hardening (BLOCKING)

1. Introduce unified PolicyDecision model across all modules.

2. Replace all boolean returns with typed decision objects.

3. Introduce strict error code unions (no string-based codes).

4. Split IdentityPolicyEngine into:
   - PasswordComplexityEngine
   - PasswordRotationEngine
   - PasswordExpiryEngine

5. Introduce trace/debug evaluation support (opt-in, zero overhead when disabled).

6. Normalize async model across all public APIs.

7. Add fail-open / fail-closed strategy configuration.

8. Enforce deep immutable configuration at runtime.

---

## Phase 1 - Quality Gates

1. Add property-based testing for:
   - complexity validation
   - rotation logic
   - expiry lifecycle

2. Add contract tests for extension interfaces and external comparators.

3. Add determinism verification tests (same input → same output).

4. Add CI matrix for multiple Node.js LTS versions.

---

## Phase 2 - Policy Hardening

1. Add configurable lower-case requirement (requireLowercase).

2. Add configurable maximum length (maxLength).

3. Add configurable deny-lists.

4. Add repeated/sequential character detection rules.

5. Add deterministic normalization pipeline:
   - trim first
   - unicode normalization second
   - metric evaluation last

---

## Phase 3 - Rotation and Reuse Controls

1. Enforce minimum password age before change.

2. Extend history comparison strategy interface.

3. Add bulk-history comparison helper.

4. Add optional substring blocking from previous secrets.

---

## Phase 4 - Expiry Lifecycle

1. Add warning window calculation (daysUntilExpiry).

2. Add grace period helpers.

3. Add explicit lifecycle states:
   - valid
   - warning
   - grace
   - expired

4. Keep UTC-safe calendar utilities.

---

## Phase 5 - Audit and Observability

1. Introduce strongly typed audit event schema:
   - complexity
   - rotation
   - expiry
   - minimumPasswordAge
   - gracePeriod

2. Ensure audit includes:
   - policyVersion
   - timestamp
   - outcome
   - structured metadata

3. Keep audit callback non-blocking and failure-isolated.

---

## Phase 6 - Extension Isolation (OUT OF CORE)

Move to future external package:

- entropy validators (zxcvbn-like)
- compromised password checks
- k-anonymity integrations

Core must remain:
- deterministic
- dependency-free
- predictable

---

## Phase 7 - Adapter Ecosystem (NON-BLOCKING)

1. Provide minimal adapter examples:
   - Express
   - Fastify
   - custom runtime

2. Avoid framework coupling in core.

---

## Compatibility Commitment

The following must always hold:

1. Framework agnosticism in core modules.
2. No mandatory database or ORM dependencies.
3. Deterministic execution for core policy evaluation.
4. Strong typing across all public APIs.
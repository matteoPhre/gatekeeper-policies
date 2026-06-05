# Roadmap

This roadmap focuses on strengthening policy controls while preserving the current framework-agnostic architecture.

## Phase 1 - Policy Hardening

1. [x] Add configurable lower-case requirement (`requireLowercase`).
2. [x] Add configurable maximum length (`maxLength`) to mitigate abuse scenarios.
3. [x] Add configurable deny-lists for weak/common patterns.
4. [x] Add repeated/sequential character detection rules.
5. [x] Add optional normalization rules (trim, unicode normalization).

## Phase 2 - Rotation and Reuse Controls

1. [x] Add policy option to enforce minimum password age before change.
2. Add optional history comparison strategy interface for advanced stores.
3. Add bulk-history comparison helper for optimized remote adapters.
4. Add optional policy to block substrings from previous secrets.

## Phase 3 - Expiry Lifecycle Extensions

1. Add warning window calculation (`daysUntilExpiry`).
2. Add helper APIs for grace periods after expiry.
3. Add explicit result type for expiry states (`valid`, `warning`, `expired`, `grace`).
4. Add utilities for UTC-safe calendar-based policies.

## Phase 4 - Operational and Security Features

1. Add optional audit event callbacks for compliance logging.
2. Add structured error codes across all validations.
3. Add constant-time utility helpers for safer comparisons when needed.
4. Add threat-focused examples for brute-force and credential-stuffing controls.

## Phase 5 - Adapter Ecosystem and DX

1. Add additional integration examples (Koa, Hono, Nest middleware layer).
2. Add typed adapter templates to accelerate custom framework integration.
3. Add a dedicated examples directory with runnable mini-projects.
4. Add API reference generation and versioned docs.

## Phase 6 - Quality and Compatibility

1. Add contract tests to validate third-party adapters.
2. Add property-based tests for complexity and rotation edge cases.
3. Add CI matrix for multiple Node LTS versions.
4. Add semantic-release workflow and changelog automation.

## Compatibility Commitment

All future changes should preserve:
1. Framework agnosticism in core modules.
2. No mandatory database or ORM dependencies.
3. Backward-compatible APIs where feasible, with clear migration notes for breaking changes.

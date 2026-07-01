# gatekeeper-policies

`@matteophre/gatekeeper-policies` is a TypeScript library for enterprise-grade password lifecycle management in Node.js applications.

The library is intentionally unopinionated:
- no ORM dependencies
- no database drivers
- no hard coupling to a specific HTTP framework

Persistence and request extraction are delegated to the host application through typed callbacks.

## Scope

The current implementation covers:
- password complexity validation (with structured issue codes)
- password rotation against history hashes
- password expiry evaluation (including warning and grace states)
- HTTP-agnostic middleware/hook factories
- constant-time comparison helpers for host-managed secret checks
- typed validation outcomes for policy violations

## Architecture

The project is split into logical modules under `src/`:
- `src/types/interfaces.ts`: public contracts, options, and callback types
- `src/policy/engine.ts`: pure policy utilities, validators, and option resolution
- `src/policy/identity-policy-engine.ts`: orchestration class (`IdentityPolicyEngine`)
- `src/utils/constant-time.ts`: timing-safe comparison helpers
- `src/adapters/http-adapters.ts`: transport helpers for request pipeline integration

Internal helpers (not part of the public surface, but relevant to behavior):
- `src/internal/audit.ts`: fire-and-forget audit event dispatch used by the engine

An index entrypoint exports all public modules:
- `src/index.ts`

## Installation

```bash
npm install @matteophre/gatekeeper-policies
```

Runtime requirements:

- Node.js `>=22`
- npm `>=10`

## Release and Publish (npm)

Recommended release sequence:

```bash
npm ci
npm run release:check
npm run publish:npm:dry
```

Publish command:

```bash
npm run publish:npm
```

Available scripts:

- `npm run security:audit:prod`: audits production dependency surface
- `npm run security:audit:dev`: audits full development dependency tree
- `npm run security:pack`: verifies package contents with `npm pack --dry-run`
- `npm run release:check`: build + tests + production audit + package dry run

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- `1.x.x`: stable public API; breaking changes only on major bumps
- patch releases: bug fixes and backward-compatible documentation or test updates
- minor releases: backward-compatible features

Current published version: see `package.json`.

Suggested release flow:

```bash
npm run release:check
npm version patch   # or minor / major
git push origin main --follow-tags
npm run publish:npm
```

Releases are currently published manually from a trusted local environment.

Manual publish prerequisites:

- npm account with publish permissions on `@matteophre`
- npm account email must be verified
- run publish from a local authenticated session (`npm whoami`)

## Quick Start

### 1. Engine only

Use this mode if you only need policy evaluation in application services.

```ts
import { IdentityPolicyEngine } from "@matteophre/gatekeeper-policies";

const engine = new IdentityPolicyEngine({
	persistence: {
		async getPasswordHistory(userId: string) {
			return []; // your database read
		},
		async saveNewPassword(userId: string, newHash: string) {
			// your database write
		},
	},
});

const complexity = engine.validateComplexity("StrongPassword#2026");
const canRotate = await engine.validateRotation(
	"StrongPassword#2026",
	"user-123",
	async (plain, hash) => {
		// wrap bcrypt.compare / argon2.verify / custom verify
		return false;
	},
);
const expired = engine.isPasswordExpired("2026-03-01T00:00:00.000Z");
```

### 2. Generic pipeline integration

Use this mode for custom runtimes and in-house HTTP abstractions.

```ts
import {
	createStatusJsonExpiryMiddleware,
	IdentityPolicyEngine,
} from "@matteophre/gatekeeper-policies";

type RequestShape = {
	auth: {
		userId: string;
		passwordCreatedAt: string;
	};
};

type ResponseShape = {
	status: (code: number) => {
		json: (body: unknown) => unknown;
	};
};

const engine = new IdentityPolicyEngine({
	persistence: {
		async getPasswordHistory() {
			return [];
		},
		async saveNewPassword() {
			return;
		},
	},
});

const middleware = createStatusJsonExpiryMiddleware<RequestShape, ResponseShape>({
	getUserIdAndDateFn: async (req) => ({
		userId: req.auth.userId,
		passwordCreatedAt: new Date(req.auth.passwordCreatedAt),
	}),
	isPasswordExpired: (createdAt) => engine.isPasswordExpired(createdAt),
});
```

### 3. Framework integration examples

Reference examples are available in test files:

- Express and Fastify integration: `tests/integration-frameworks.test.ts`
- Custom runtime integration: `tests/integration-custom-runtime.test.ts`
- Brute-force and credential-stuffing patterns: `tests/security.test.ts`

These examples are intended as implementation references and do not introduce framework coupling in the core library.

## Core Concepts

### 1. Engine Configuration

`IdentityPolicyEngine` accepts policy options and persistence callbacks:

- `minLength` (default `12`)
- `maxLength` (default `128`)
- `normalizeTrim` (default `false`)
- `normalizeUnicode` (default `false`)
- `unicodeNormalizationForm` (default `NFKC`)
- `requireUppercase` (default `true`)
- `requireLowercase` (default `true`)
- `requireNumbers` (default `true`)
- `requireSymbols` (default `true`)
- `denyList` (default `[]`, case-insensitive substring matching)
- `preventRepeatedChars` (default `false`)
- `maxRepeatedChars` (default `3`)
- `preventSequentialChars` (default `false`)
- `maxSequentialChars` (default `3`)
- `expiryDays` (default `90`)
- `expiryWarningDays` (default `0`, disables warning state before expiry)
- `gracePeriodDays` (default `0`, disables post-expiry grace window)
- `minimumPasswordAgeDays` (default `0`, disables minimum-age enforcement)
- `historyLimit` (default `5`)
- `blockSubstringsFromPreviousSecrets` (default `false`)
- `minPreviousSecretSubstringLength` (default `4`)
- `persistence.getPasswordHistory(userId)`
- `persistence.saveNewPassword(userId, newHash)`
- `persistence.getPreviousPasswordSubstrings(userId)` when substring blocking is enabled
- `auditEventCallback(event)` for compliance logging and observability hooks
- `entropyValidator(context)` for optional host-managed entropy/strength checks
- `compromisedPasswordValidator(context)` for optional host-managed breach checks

`auditEventCallback` is optional and fire-and-forget: the engine clones each event before invoking the callback, enriches it with `policyVersion` and `timestamp`, and ignores callback failures so validation behavior stays deterministic.

### 2. Complexity Validation

`validateComplexity(password)` returns:

```ts
{ isValid: boolean; errors: string[]; issues?: Array<{ code: string; message: string; meta?: Record<string, unknown> }> }
```

`errors` stays for human-readable output; `issues` adds stable machine-readable codes for host-side mapping and logging, while `meta` carries rule-specific context (for example required thresholds and measured values).

For intrinsic complexity extensions, `validateComplexityWithExtensions(password)` applies optional host-managed validators:

- `entropyValidator({ password, normalizedPassword })`
- `compromisedPasswordValidator({ password, normalizedPassword })`

The engine also provides adapters:

- `createScoreBasedEntropyValidator(scoreFn, minimumScore)` for zxcvbn-compatible score sources
- `createCompromisedPasswordDictionaryValidator(dictionary)` for local compromised dictionaries

### 3. Rotation Validation

`validateRotation(plainPassword, userId, comparator)`:
- retrieves password history from application callback
- compares plain password against previous hashes or delegates to a strategy object
- blocks reuse when a match is found

`comparator` can be either:

- a `PasswordCompareFn` for per-hash checks (bcrypt, argon2, custom verification)
- a `PasswordHistoryComparisonStrategy` for advanced stores that can evaluate reuse in bulk or remotely

For advanced stores, `validateRotation(...)` also accepts a strategy object with `isReused(context)` so callers can offload bulk or remote comparison logic.

For optimized remote adapters, `createBulkPasswordHistoryComparisonStrategy(compareFn)` adapts a single bulk comparison callback into a `PasswordHistoryComparisonStrategy`.

When `blockSubstringsFromPreviousSecrets` is enabled, the engine also checks `persistence.getPreviousPasswordSubstrings(userId)` and blocks candidates containing sufficiently long fragments from previous secrets.

### 4. Expiry Evaluation

`isPasswordExpired(passwordCreatedAt)` accepts `Date | string` and evaluates expiration with `expiryDays`.

`daysUntilExpiry(passwordCreatedAt)` accepts `Date | string` and returns remaining days before expiry (`0` when expired).

`isWithinGracePeriod(passwordCreatedAt)` returns whether the password is expired but still inside the configured grace window.

`daysRemainingInGracePeriod(passwordCreatedAt)` returns remaining grace days (`0` when not in grace).

`evaluateExpiryState(passwordCreatedAt)` returns explicit lifecycle state: `valid`, `warning`, `grace`, `expired`.

`evaluatePasswordExpiryDecision(passwordCreatedAt)` returns a typed success/failure outcome for expiry enforcement.

### 5. Minimum Password Age

`isMinimumPasswordAgeSatisfied(passwordCreatedAt)` accepts `Date | string` and enforces the optional `minimumPasswordAgeDays` policy before allowing a password change.

`evaluateMinimumPasswordAgeDecision(passwordCreatedAt)` returns a typed success/failure outcome for minimum-age enforcement.

### 6. Typed Validation Outcomes

In addition to the boolean/string-based APIs above, the engine exposes additive outcome helpers that return structured `{ valid: true }` or `{ valid: false, reason, details }` shapes (complexity uses `reasons[]` because multiple rules can fail at once):

- `evaluateComplexityOutcome(password)` → `PasswordComplexityValidationOutcome`
- `evaluateRotationOutcome(plainPassword, userId, comparator)` → `PasswordRotationValidationOutcome`
- `evaluateMinimumPasswordAgeOutcome(passwordCreatedAt)` → `MinimumPasswordAgeValidationOutcome`
- `evaluatePasswordExpiryDecision(passwordCreatedAt)` → `PasswordExpiryValidationOutcome`
- `evaluateMinimumPasswordAgeDecision(passwordCreatedAt)` → `MinimumPasswordAgeValidationOutcome`

Existing methods (`validateComplexity`, `validateRotation`, `isMinimumPasswordAgeSatisfied`, …) are unchanged.

### 7. Security Utilities

For host-managed secret or token comparisons, the library exports timing-safe helpers backed by Node.js `crypto.timingSafeEqual`:

- `constantTimeEqual(left, right)` for `string | Uint8Array` values
- `constantTimeStringEqual(left, right)` for UTF-8 string values

These utilities live in `src/utils/constant-time.ts` and are intentionally generic: use them in your auth layer, not inside core policy rules.

## Usage

### Engine Example

```ts
import { IdentityPolicyEngine } from "@matteophre/gatekeeper-policies";

const engine = new IdentityPolicyEngine({
	minLength: 12,
	expiryDays: 90,
	historyLimit: 5,
	persistence: {
		async getPasswordHistory(userId: string) {
			return []; // load from your store
		},
		async saveNewPassword(userId: string, newHash: string) {
			// persist in your store
		},
	},
	auditEventCallback: async (event) => {
		console.log(`[audit] ${event.type}:${event.outcome}`, event.details ?? {});
	},
});

const complexity = engine.validateComplexity("StrongPassword#2026");
const expired = engine.isPasswordExpired("2026-03-01T00:00:00.000Z");
```

### Intrinsic Complexity Extensions Example

```ts
import {
	createCompromisedPasswordDictionaryValidator,
	createScoreBasedEntropyValidator,
	IdentityPolicyEngine,
} from "@matteophre/gatekeeper-policies";

const engine = new IdentityPolicyEngine({
	persistence: {
		async getPasswordHistory() {
			return [];
		},
		async saveNewPassword() {
			return;
		},
	},
	entropyValidator: createScoreBasedEntropyValidator(async (password) => {
		// Plug your zxcvbn-like scoring source here (0..4 for example)
		return password.length > 14 ? 4 : 2;
	}, 3),
	compromisedPasswordValidator: createCompromisedPasswordDictionaryValidator([
		"password123",
		"letmein",
		"strongpassword#2026",
	]),
});

const result = await engine.validateComplexityWithExtensions("StrongPassword#2026");
// result.issues includes PASSWORD_ENTROPY_TOO_LOW and/or PASSWORD_COMPROMISED when triggered
```

### Typed Outcome Example

```ts
import { IdentityPolicyEngine } from "@matteophre/gatekeeper-policies";

const engine = new IdentityPolicyEngine({
  persistence: {
    async getPasswordHistory() {
      return [];
    },
    async saveNewPassword() {
      return;
    },
  },
});

const complexityOutcome = engine.evaluateComplexityOutcome("short");
if (!complexityOutcome.valid) {
  console.log(complexityOutcome.reasons.map((issue) => issue.code));
}

const rotationOutcome = await engine.evaluateRotationOutcome(
  "candidate",
  "user-123",
  async () => false,
);
if (!rotationOutcome.valid) {
  console.log(rotationOutcome.reason, rotationOutcome.details);
}
```

### HTTP Pipeline Integration

The library provides generic primitives:

- `createStatusJsonExpiryMiddleware(...)`
- `createCodeSendExpiryHook(...)`
- `evaluatePasswordExpiry(...)`

They can be attached to any framework that offers compatible request/response contracts.

## API Reference

### IdentityPolicyEngine

| Method | Signature | Description |
| --- | --- | --- |
| constructor | `new IdentityPolicyEngine(options)` | Creates an engine instance with policy settings and persistence callbacks. |
| getConfig | `getConfig(): Readonly<ResolvedIdentityPolicyEngineOptions>` | Returns the resolved runtime configuration (defaults applied). |
| validateComplexity | `validateComplexity(password: string): ComplexityValidationResult` | Evaluates password complexity against the active policy. |
| evaluateComplexityOutcome | `evaluateComplexityOutcome(password: string): PasswordComplexityValidationOutcome` | Returns a typed success/failure outcome for complexity validation. |
| validateComplexityWithExtensions | `validateComplexityWithExtensions(password: string): Promise<ComplexityValidationResult>` | Evaluates base complexity and optional intrinsic complexity extensions (`entropyValidator`, `compromisedPasswordValidator`). |
| validateRotation | `validateRotation(plainPassword: string, userId: string, comparator: PasswordCompareFn | PasswordHistoryComparisonStrategy): Promise<boolean>` | Prevents password reuse by comparing candidate value with historical hashes or a caller-provided strategy object. |
| evaluateRotationOutcome | `evaluateRotationOutcome(plainPassword: string, userId: string, comparator: PasswordCompareFn | PasswordHistoryComparisonStrategy): Promise<PasswordRotationValidationOutcome>` | Returns a typed success/failure outcome for rotation validation. |
| isMinimumPasswordAgeSatisfied | `isMinimumPasswordAgeSatisfied(passwordCreatedAt: Date | string): boolean` | Enforces the optional minimum-age requirement before a password can be changed. |
| evaluateMinimumPasswordAgeOutcome | `evaluateMinimumPasswordAgeOutcome(passwordCreatedAt: Date | string): MinimumPasswordAgeValidationOutcome` | Returns a typed success/failure outcome for minimum-age enforcement. |
| isPasswordExpired | `isPasswordExpired(passwordCreatedAt: Date | string): boolean` | Checks whether password age exceeds configured expiry window. |
| daysUntilExpiry | `daysUntilExpiry(passwordCreatedAt: Date | string): number` | Returns remaining days before expiry, clamped to `0` when already expired. |
| isWithinGracePeriod | `isWithinGracePeriod(passwordCreatedAt: Date | string): boolean` | Returns whether the password is expired and still within the configured grace period. |
| daysRemainingInGracePeriod | `daysRemainingInGracePeriod(passwordCreatedAt: Date | string): number` | Returns remaining grace days, clamped to `0` when outside grace. |
| evaluateExpiryState | `evaluateExpiryState(passwordCreatedAt: Date | string): PasswordExpiryStateResult` | Returns explicit lifecycle state (`valid`, `warning`, `grace`, `expired`) with remaining-day metrics. |

Audit events are emitted with these `type` values: `complexity`, `rotation`, `expiry`, `minimumPasswordAge`, and `gracePeriod`.

### Utility Functions

| Function | Signature | Description |
| --- | --- | --- |
| normalizePasswordCreatedAt | `normalizePasswordCreatedAt(passwordCreatedAt: Date | string): Date` | Normalizes and validates date input used by expiry logic. |
| toUtcStartOfDay | `toUtcStartOfDay(value: Date | string): Date` | Normalizes a timestamp to UTC midnight (`00:00:00.000Z`) for calendar-safe policy checks. |
| addUtcCalendarDays | `addUtcCalendarDays(value: Date | string, days: number): Date` | Adds whole calendar days in UTC semantics, avoiding local timezone drift. |
| daysBetweenUtcCalendarDates | `daysBetweenUtcCalendarDates(start: Date | string, end: Date | string): number` | Returns day difference between UTC-normalized calendar dates. |
| createScoreBasedEntropyValidator | `createScoreBasedEntropyValidator(scoreFn, minimumScore): PasswordEntropyValidator` | Wraps score providers (zxcvbn-compatible) into the intrinsic complexity validator contract. |
| createCompromisedPasswordDictionaryValidator | `createCompromisedPasswordDictionaryValidator(dictionary): PasswordCompromisedPasswordValidator` | Creates a local dictionary-based compromised-password validator for host-managed checks. |
| createBulkPasswordHistoryComparisonStrategy | `createBulkPasswordHistoryComparisonStrategy(compareFn): PasswordHistoryComparisonStrategy` | Adapts a bulk history comparison callback into a rotation strategy. |
| normalizePasswordInput | `normalizePasswordInput(value, config): string` | Applies configured trim/unicode normalization before policy evaluation. |
| constantTimeEqual | `constantTimeEqual(left, right): boolean` | Compares `string | Uint8Array` values in constant time. |
| constantTimeStringEqual | `constantTimeStringEqual(left, right): boolean` | Compares UTF-8 strings in constant time. |
| evaluatePasswordExpiry | `evaluatePasswordExpiry(request, options): Promise<{ expired: boolean; subject: PasswordSubjectContext; expiredResult?: TExpiredResult }>` | Evaluates expiry in a transport-agnostic pipeline and invokes `onExpired` when needed. |

### Transport Factories

| Factory | Signature | Description |
| --- | --- | --- |
| createStatusJsonExpiryMiddleware | `createStatusJsonExpiryMiddleware(options): (request, response, next) => Promise<void>` | Builds middleware for pipelines exposing `response.status(...).json(...)`. |
| createCodeSendExpiryHook | `createCodeSendExpiryHook(options): (request, reply) => Promise<void>` | Builds hook-style handler for transports exposing `reply.code(...).send(...)`. |

### Core Type Contracts

Important contracts are defined in `src/types/interfaces.ts`:

- `PasswordPolicyConfig`
- `PasswordPersistenceCallbacks`
- `IdentityPolicyEngineOptions`
- `ResolvedIdentityPolicyEngineOptions`
- `PasswordAuditEvent`
- `PasswordAuditEventCallback`
- `PasswordEntropyValidator`
- `PasswordCompromisedPasswordValidator`
- `PasswordValidationIssue`
- `ComplexityValidationResult`
- `PolicyValidationOutcome`
- `PasswordComplexityValidationOutcome`
- `PasswordRotationValidationOutcome`
- `MinimumPasswordAgeValidationOutcome`
- `PasswordCompareFn`
- `PasswordHistoryComparator`
- `PasswordHistoryComparisonStrategy`
- `BulkPasswordHistoryCompareFn`
- `PasswordExpiryStateResult`
- `CreateStatusJsonExpiryMiddlewareOptions`
- `CreateCodeSendExpiryHookOptions`

## Implemented Testing Strategy

The repository includes:

- unit tests for engine behavior: `tests/engine.test.ts`
- unit tests for timing-safe helpers: `tests/constant-time.test.ts`
- reference examples for threat controls: `tests/security.test.ts`
- unit tests for transport helpers: `tests/http-adapters-unit.test.ts`
- integration examples with real frameworks: `tests/integration-frameworks.test.ts`
- integration example with a custom runtime: `tests/integration-custom-runtime.test.ts`
- contract tests for extension interfaces and comparator adapters: `tests/contracts.test.ts`
- determinism verification tests for repeated evaluations: `tests/determinism.test.ts`
- property-based quality gates for complexity, rotation, and expiry: `tests/property-based.test.ts`

Current status:
- all tests pass with Vitest

## Design Notes

- The core never imports framework-specific or persistence-specific packages.
- Security-relevant decisions are explicit and injected by the host application.
- Public contracts are strongly typed and built for dependency injection.

## Roadmap

Planned future enhancements are documented in the merged canonical roadmap:

- `ROADMAP.md`
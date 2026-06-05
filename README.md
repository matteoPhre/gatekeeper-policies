# gatekeeper-policies

`@matteophre/gatekeeper-policies` is a TypeScript library for enterprise-grade password lifecycle management in Node.js applications.

The library is intentionally unopinionated:
- no ORM dependencies
- no database drivers
- no hard coupling to a specific HTTP framework

Persistence and request extraction are delegated to the host application through typed callbacks.

## Scope

The current implementation covers:
- password complexity validation
- password rotation against history hashes
- password expiry evaluation
- HTTP-agnostic middleware/hook factories

## Architecture

The project is split into three core modules:
- `src/interfaces.ts`: public contracts, options, and callback types
- `src/engine.ts`: pure business logic (`IdentityPolicyEngine`)
- `src/http-adapters.ts`: transport helpers for request pipeline integration

An index entrypoint exports all modules:
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

This project follows Semantic Versioning with a practical rule for early releases:

- `0.y.z`: initial development phase, breaking changes can happen on minor bumps
- `1.0.0+`: stable API contract, breaking changes only on major bumps

Current baseline release target:

- `0.0.2`: first tagged public baseline for scoped npm publish

Suggested release flow:

```bash
npm version patch
git push origin main --follow-tags
```

Or manually for the first baseline tag:

```bash
git tag -a v0.0.2 -m "release: v0.0.2"
git push origin v0.0.2
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

- Express and Fastify integration: `tests/integration.frameworks.test.ts`
- Custom runtime integration: `tests/integration.custom-runtime.test.ts`

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
- `historyLimit` (default `5`)
- `persistence.getPasswordHistory(userId)`
- `persistence.saveNewPassword(userId, newHash)`

### 2. Complexity Validation

`validateComplexity(password)` returns:

```ts
{ isValid: boolean; errors: string[] }
```

### 3. Rotation Validation

`validateRotation(plainPassword, userId, compareFn)`:
- retrieves password history from application callback
- compares plain password against previous hashes
- blocks reuse when a match is found

`compareFn` is intentionally injected and can wrap bcrypt, argon2 verification, or any custom strategy.

### 4. Expiry Evaluation

`isPasswordExpired(passwordCreatedAt)` accepts `Date | string` and evaluates expiration with `expiryDays`.

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
});

const complexity = engine.validateComplexity("StrongPassword#2026");
const expired = engine.isPasswordExpired("2026-03-01T00:00:00.000Z");
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
| validateComplexity | `validateComplexity(password: string): { isValid: boolean; errors: string[] }` | Evaluates password complexity against the active policy. |
| validateRotation | `validateRotation(plainPassword: string, userId: string, compareFn: PasswordCompareFn): Promise<boolean>` | Prevents password reuse by comparing candidate value with historical hashes. |
| isPasswordExpired | `isPasswordExpired(passwordCreatedAt: Date | string): boolean` | Checks whether password age exceeds configured expiry window. |

### Utility Functions

| Function | Signature | Description |
| --- | --- | --- |
| normalizePasswordCreatedAt | `normalizePasswordCreatedAt(passwordCreatedAt: Date | string): Date` | Normalizes and validates date input used by expiry logic. |
| evaluatePasswordExpiry | `evaluatePasswordExpiry(request, options): Promise<{ expired: boolean; subject: PasswordSubjectContext; expiredResult?: TExpiredResult }>` | Evaluates expiry in a transport-agnostic pipeline and invokes `onExpired` when needed. |

### Transport Factories

| Factory | Signature | Description |
| --- | --- | --- |
| createStatusJsonExpiryMiddleware | `createStatusJsonExpiryMiddleware(options): (request, response, next) => Promise<void>` | Builds middleware for pipelines exposing `response.status(...).json(...)`. |
| createCodeSendExpiryHook | `createCodeSendExpiryHook(options): (request, reply) => Promise<void>` | Builds hook-style handler for transports exposing `reply.code(...).send(...)`. |

### Core Type Contracts

Important contracts are defined in `src/interfaces.ts`:

- `PasswordPolicyConfig`
- `PasswordPersistenceCallbacks`
- `IdentityPolicyEngineOptions`
- `PasswordCompareFn`
- `CreateStatusJsonExpiryMiddlewareOptions`
- `CreateCodeSendExpiryHookOptions`

## Implemented Testing Strategy

The repository includes:

- unit tests for engine behavior: `tests/engine.test.ts`
- unit tests for transport helpers: `tests/http-adapters.unit.test.ts`
- integration examples with real frameworks: `tests/integration.frameworks.test.ts`
- integration example with a custom runtime: `tests/integration.custom-runtime.test.ts`

Current status:
- all tests pass with Vitest

## Design Notes

- The core never imports framework-specific or persistence-specific packages.
- Security-relevant decisions are explicit and injected by the host application.
- Public contracts are strongly typed and built for dependency injection.

## Roadmap

Planned future enhancements are documented in:

- `ROADMAP.md`
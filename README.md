# gatekeeper-policies

`@matteophre/gatekeeper-policies` is a TypeScript library for password lifecycle policies in Node.js applications.

It is intentionally unopinionated:
- no ORM dependencies
- no database drivers
- no framework lock-in

Your app provides persistence and credential checks via typed callbacks.

## Installation

```bash
npm install @matteophre/gatekeeper-policies
```

Runtime requirements:
- Node.js `>=22`
- npm `>=10`

## What It Covers

- password complexity validation
- password rotation/history checks
- password expiry, warning, and grace-period decisions
- transport-agnostic middleware/hook factories
- constant-time comparison utilities

## Quick Start

```ts
import { IdentityPolicyEngine } from "@matteophre/gatekeeper-policies";

const engine = new IdentityPolicyEngine({
  expiryDays: 90,
  historyLimit: 5,
  persistence: {
    async getPasswordHistory(userId: string) {
      return [];
    },
    async saveNewPassword(userId: string, newHash: string) {
      return;
    },
  },
});

const complexity = engine.validateComplexity("StrongGate#2026");
const canRotate = await engine.validateRotation(
  "StrongGate#2026",
  "user-123",
  async (_plain, _hash) => false,
);
const expiryDecision = engine.evaluatePasswordExpiryDecision("2026-03-01T00:00:00.000Z");
```

## Main APIs

Core engine:
- `validateComplexity(password)`
- `validateRotation(plainPassword, userId, comparator)`
- `evaluateComplexityOutcome(password)`
- `evaluateRotationOutcome(plainPassword, userId, comparator)`
- `evaluatePasswordExpiryDecision(passwordCreatedAt)`
- `evaluateMinimumPasswordAgeDecision(passwordCreatedAt)`

Transport adapters:
- `createStatusJsonExpiryMiddleware(...)`
- `createCodeSendExpiryHook(...)`
- `evaluatePasswordExpiry(...)`

Utilities:
- `constantTimeEqual(left, right)`
- `constantTimeStringEqual(left, right)`

## Development

Useful scripts:

```bash
npm run build
npm run test
npm run release:check
```

Release and publish:

```bash
npm ci
npm run release:check
npm run publish:npm:dry
npm run publish:npm
```

## Testing

The suite includes unit, contract, determinism, property-based, and integration coverage.

Run all tests:

```bash
npm test
```

## Playgrounds

Framework-specific playgrounds are maintained in separate repositories:
- `gatekeeper-policies-express`
- `gatekeeper-policies-fastify`

## Roadmap

See `ROADMAP.md`.

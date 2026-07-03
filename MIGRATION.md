# Migration Guide: Legacy Wrappers to Typed Decisions

This guide documents the migration path from legacy boolean/array wrappers to typed decision outcomes.

## Deprecation Timeline

- Deprecated in `1.2.x`: legacy wrappers on `IdentityPolicyEngine`.
- Planned removal target: `v2.0.0`.

You can enable runtime warnings with:

```ts
const engine = new IdentityPolicyEngine({
  deprecationWarnings: true,
  persistence: {
    async getPasswordHistory() {
      return [];
    },
    async saveNewPassword() {
      return;
    },
  },
});
```

## Method Mapping

| Legacy method | Typed replacement |
| --- | --- |
| `validateComplexity(password)` | `evaluateComplexityOutcome(password)` |
| `validateRotation(plainPassword, userId, comparator)` | `evaluateRotationOutcome(plainPassword, userId, comparator)` |
| `isPasswordExpired(passwordCreatedAt)` | `evaluatePasswordExpiryDecision(passwordCreatedAt)` |
| `isMinimumPasswordAgeSatisfied(passwordCreatedAt)` | `evaluateMinimumPasswordAgeDecision(passwordCreatedAt)` |
| `isWithinGracePeriod(passwordCreatedAt)` | `evaluateExpiryState(passwordCreatedAt)` |
| `daysUntilExpiry(passwordCreatedAt)` | `evaluateExpiryState(passwordCreatedAt)` |
| `daysRemainingInGracePeriod(passwordCreatedAt)` | `evaluateExpiryState(passwordCreatedAt)` |

## Example Migration

Before:

```ts
const canRotate = await engine.validateRotation(password, userId, compareFn);
if (!canRotate) {
  return { error: "Password reuse not allowed" };
}
```

After:

```ts
const decision = await engine.evaluateRotationOutcome(password, userId, compareFn);
if (!decision.valid) {
  return { error: decision.reason, details: decision.details };
}
```

The typed APIs are now the canonical interface and provide stable machine-readable reasons for downstream systems.

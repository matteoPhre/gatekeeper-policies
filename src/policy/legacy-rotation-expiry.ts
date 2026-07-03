import type {
  MinimumPasswordAgeValidationOutcome,
  PasswordCreatedAtInput,
  PasswordExpiryStateResult,
  PasswordExpiryValidationOutcome,
  PasswordHistoryComparator,
  PasswordRotationValidationOutcome,
  ResolvedIdentityPolicyEngineOptions,
} from "../types/interfaces.js";
import { emitAuditEvent } from "../internal/audit.js";
import { emitMetricEvent } from "../internal/metrics.js";
import {
  hasBlockedPreviousSecretSubstring,
  isPasswordCompareFn,
  MS_PER_DAY,
  normalizePasswordCreatedAt,
  normalizePasswordInput,
} from "./engine.js";

export async function evaluateLegacyRotationOutcome(
  plainPassword: string,
  userId: string,
  comparator: PasswordHistoryComparator,
  config: ResolvedIdentityPolicyEngineOptions,
): Promise<PasswordRotationValidationOutcome> {
  const normalizedPlainPassword = normalizePasswordInput(plainPassword, config);

  if (config.blockSubstringsFromPreviousSecrets) {
    const previousSubstrings =
      await config.persistence.getPreviousPasswordSubstrings?.(userId);

    if (
      hasBlockedPreviousSecretSubstring(
        normalizedPlainPassword,
        previousSubstrings,
        config,
      )
    ) {
      void emitAuditEvent(config.auditEventCallback, {
        type: "rotation",
        userId,
        outcome: "fail",
        details: {
          mode: "previousSubstring",
          historyLimit: config.historyLimit,
        },
      });

      void emitMetricEvent(config.metricsHook, {
        name: "password.rotation.evaluations",
        type: "counter",
        value: 1,
        attributes: {
          outcome: "fail",
          mode: "previousSubstring",
        },
      });

      return {
        valid: false,
        reason: "PASSWORD_CONTAINS_PREVIOUS_SUBSTRING",
        details: {
          minPreviousSecretSubstringLength:
            config.minPreviousSecretSubstringLength,
        },
      };
    }
  }

  const history = await config.persistence.getPasswordHistory(userId);
  const limitedHistory = history.slice(0, config.historyLimit);

  if (!isPasswordCompareFn(comparator)) {
    const isReused = await comparator.isReused({
      userId,
      plainPassword,
      normalizedPassword: normalizedPlainPassword,
      history: limitedHistory,
      historyLimit: config.historyLimit,
    });

    if (isReused) {
      void emitAuditEvent(config.auditEventCallback, {
        type: "rotation",
        userId,
        outcome: "fail",
        details: {
          mode: "strategy",
          historyLimit: config.historyLimit,
        },
      });

      void emitMetricEvent(config.metricsHook, {
        name: "password.rotation.evaluations",
        type: "counter",
        value: 1,
        attributes: {
          outcome: "fail",
          mode: "strategy",
        },
      });

      return {
        valid: false,
        reason: "PASSWORD_REUSED",
        details: {
          mode: "strategy",
          historyLimit: config.historyLimit,
        },
      };
    }

    void emitAuditEvent(config.auditEventCallback, {
      type: "rotation",
      userId,
      outcome: "pass",
      details: {
        mode: "strategy",
        historyLimit: config.historyLimit,
      },
    });

    void emitMetricEvent(config.metricsHook, {
      name: "password.rotation.evaluations",
      type: "counter",
      value: 1,
      attributes: {
        outcome: "pass",
        mode: "strategy",
      },
    });

    return { valid: true };
  }

  for (const previousHash of limitedHistory) {
    const isReused = await comparator(normalizedPlainPassword, previousHash);
    if (isReused) {
      void emitAuditEvent(config.auditEventCallback, {
        type: "rotation",
        userId,
        outcome: "fail",
        details: {
          mode: "compareFn",
          historyLimit: config.historyLimit,
        },
      });

      void emitMetricEvent(config.metricsHook, {
        name: "password.rotation.evaluations",
        type: "counter",
        value: 1,
        attributes: {
          outcome: "fail",
          mode: "compareFn",
        },
      });

      return {
        valid: false,
        reason: "PASSWORD_REUSED",
        details: {
          mode: "compareFn",
          historyLimit: config.historyLimit,
        },
      };
    }
  }

  void emitAuditEvent(config.auditEventCallback, {
    type: "rotation",
    userId,
    outcome: "pass",
    details: {
      mode: "compareFn",
      historyLimit: config.historyLimit,
    },
  });

  void emitMetricEvent(config.metricsHook, {
    name: "password.rotation.evaluations",
    type: "counter",
    value: 1,
    attributes: {
      outcome: "pass",
      mode: "compareFn",
    },
  });

  return { valid: true };
}

export function isPasswordExpiredLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): boolean {
  const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
  const now = Date.now();
  const ageInMs = now - createdAt.getTime();
  const maxAgeInMs = config.expiryDays * MS_PER_DAY;

  const expired = ageInMs >= maxAgeInMs;

  void emitAuditEvent(config.auditEventCallback, {
    type: "expiry",
    outcome: expired ? "fail" : "pass",
    details: {
      expiryDays: config.expiryDays,
    },
  });

  void emitMetricEvent(config.metricsHook, {
    name: "password.expiry.evaluations",
    type: "counter",
    value: 1,
    attributes: {
      outcome: expired ? "fail" : "pass",
      mode: "isPasswordExpired",
    },
  });

  return expired;
}

export function daysUntilExpiryLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): number {
  const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
  const now = Date.now();
  const ageInMs = now - createdAt.getTime();
  const maxAgeInMs = config.expiryDays * MS_PER_DAY;
  const remainingMs = maxAgeInMs - ageInMs;

  if (remainingMs <= 0) {
    return 0;
  }

  const days = Math.ceil(remainingMs / MS_PER_DAY);

  void emitAuditEvent(config.auditEventCallback, {
    type: "expiry",
    outcome: "info",
    details: {
      mode: "daysUntilExpiry",
      days,
    },
  });

  return days;
}

export function evaluateLegacyExpiryState(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): PasswordExpiryStateResult {
  const daysUntilExpiry = daysUntilExpiryLegacy(passwordCreatedAt, config);
  const daysRemainingInGracePeriod =
    daysRemainingInGracePeriodLegacy(passwordCreatedAt, config);

  if (daysRemainingInGracePeriod > 0) {
    const result: PasswordExpiryStateResult = {
      state: "grace",
      daysUntilExpiry,
      daysRemainingInGracePeriod,
    };

    void emitAuditEvent(config.auditEventCallback, {
      type: "gracePeriod",
      outcome: "info",
      details: {
        state: result.state,
        daysUntilExpiry: result.daysUntilExpiry,
        daysRemainingInGracePeriod: result.daysRemainingInGracePeriod,
      },
    });

    return result;
  }

  if (isPasswordExpiredLegacy(passwordCreatedAt, config)) {
    const result: PasswordExpiryStateResult = {
      state: "expired",
      daysUntilExpiry,
      daysRemainingInGracePeriod,
    };

    void emitAuditEvent(config.auditEventCallback, {
      type: "gracePeriod",
      outcome: "info",
      details: {
        state: result.state,
        daysUntilExpiry: result.daysUntilExpiry,
        daysRemainingInGracePeriod: result.daysRemainingInGracePeriod,
      },
    });

    return result;
  }

  if (config.expiryWarningDays > 0 && daysUntilExpiry <= config.expiryWarningDays) {
    const result: PasswordExpiryStateResult = {
      state: "warning",
      daysUntilExpiry,
      daysRemainingInGracePeriod,
    };

    void emitAuditEvent(config.auditEventCallback, {
      type: "expiry",
      outcome: "info",
      details: {
        state: result.state,
        daysUntilExpiry: result.daysUntilExpiry,
        daysRemainingInGracePeriod: result.daysRemainingInGracePeriod,
      },
    });

    return result;
  }

  const result: PasswordExpiryStateResult = {
    state: "valid",
    daysUntilExpiry,
    daysRemainingInGracePeriod,
  };

  void emitAuditEvent(config.auditEventCallback, {
    type: "expiry",
    outcome: "pass",
    details: {
      state: result.state,
      daysUntilExpiry: result.daysUntilExpiry,
      daysRemainingInGracePeriod: result.daysRemainingInGracePeriod,
    },
  });

  return result;
}

export function isWithinGracePeriodLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): boolean {
  if (config.gracePeriodDays === 0 || !isPasswordExpiredLegacy(passwordCreatedAt, config)) {
    return false;
  }

  const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
  const now = Date.now();
  const ageInMs = now - createdAt.getTime();
  const maxAgeInMs = config.expiryDays * MS_PER_DAY;
  const graceWindowInMs = config.gracePeriodDays * MS_PER_DAY;
  const elapsedSinceExpiryInMs = ageInMs - maxAgeInMs;

  return elapsedSinceExpiryInMs <= graceWindowInMs;
}

export function daysRemainingInGracePeriodLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): number {
  if (!isWithinGracePeriodLegacy(passwordCreatedAt, config)) {
    return 0;
  }

  const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
  const now = Date.now();
  const ageInMs = now - createdAt.getTime();
  const maxAgeInMs = config.expiryDays * MS_PER_DAY;
  const graceWindowInMs = config.gracePeriodDays * MS_PER_DAY;
  const remainingGraceInMs = maxAgeInMs + graceWindowInMs - ageInMs;

  if (remainingGraceInMs <= 0) {
    return 0;
  }

  return Math.ceil(remainingGraceInMs / MS_PER_DAY);
}

export function isMinimumPasswordAgeSatisfiedLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): boolean {
  if (config.minimumPasswordAgeDays === 0) {
    return true;
  }

  const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
  const now = Date.now();
  const ageInMs = now - createdAt.getTime();
  const minimumAgeInMs = config.minimumPasswordAgeDays * MS_PER_DAY;

  const satisfied = ageInMs >= minimumAgeInMs;

  void emitAuditEvent(config.auditEventCallback, {
    type: "minimumPasswordAge",
    outcome: satisfied ? "pass" : "fail",
    details: {
      minimumPasswordAgeDays: config.minimumPasswordAgeDays,
    },
  });

  void emitMetricEvent(config.metricsHook, {
    name: "password.minimumPasswordAge.evaluations",
    type: "counter",
    value: 1,
    attributes: {
      outcome: satisfied ? "pass" : "fail",
    },
  });

  return satisfied;
}

export function evaluateMinimumPasswordAgeOutcomeLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): MinimumPasswordAgeValidationOutcome {
  if (isMinimumPasswordAgeSatisfiedLegacy(passwordCreatedAt, config)) {
    return { valid: true };
  }

  return {
    valid: false,
    reason: "MINIMUM_PASSWORD_AGE_NOT_SATISFIED",
    details: {
      minimumPasswordAgeDays: config.minimumPasswordAgeDays,
    },
  };
}

export function evaluatePasswordExpiryDecisionLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): PasswordExpiryValidationOutcome {
  if (isPasswordExpiredLegacy(passwordCreatedAt, config)) {
    return { valid: false, reason: "PASSWORD_EXPIRED" };
  }

  return { valid: true };
}

export function evaluateMinimumPasswordAgeDecisionLegacy(
  passwordCreatedAt: PasswordCreatedAtInput,
  config: ResolvedIdentityPolicyEngineOptions,
): MinimumPasswordAgeValidationOutcome {
  return evaluateMinimumPasswordAgeOutcomeLegacy(passwordCreatedAt, config);
}
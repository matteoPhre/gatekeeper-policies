import type {
  ComplexityValidationResult,
  IdentityPolicyEngineOptions,
  MinimumPasswordAgeValidationOutcome,
  PasswordComplexityValidationOutcome,
  PasswordCreatedAtInput,
  PasswordExpiryStateResult,
  PasswordExpiryValidationOutcome,
  PasswordHistoryComparator,
  PasswordRotationValidationOutcome,
  ResolvedIdentityPolicyEngineOptions,
} from "../types/interfaces.js";
import { emitAuditEvent } from "../internal/audit.js";
import {
  hasBlockedPreviousSecretSubstring,
  isPasswordCompareFn,
  MS_PER_DAY,
  normalizePasswordCreatedAt,
  normalizePasswordInput,
  resolveEngineOptions,
} from "./engine.js";
import {
  validateLegacyComplexity,
  validateLegacyComplexityWithExtensions,
} from "./legacy-complexity.js";

export class IdentityPolicyEngine {
  private readonly config: ResolvedIdentityPolicyEngineOptions;

  constructor(options: IdentityPolicyEngineOptions) {
    this.config = resolveEngineOptions(options);
  }

  getConfig(): Readonly<ResolvedIdentityPolicyEngineOptions> {
    return this.config;
  }

  validateComplexity(password: string): ComplexityValidationResult {
    return validateLegacyComplexity(password, this.config);
  }

  evaluateComplexityOutcome(
    password: string,
  ): PasswordComplexityValidationOutcome {
    const result = this.validateComplexity(password);

    if (result.isValid) {
      return { valid: true };
    }

    return {
      valid: false,
      reasons: result.issues ?? [],
      details: {
        errorCount: result.errors.length,
      },
    };
  }

  async validateComplexityWithExtensions(
    password: string,
  ): Promise<ComplexityValidationResult> {
    return validateLegacyComplexityWithExtensions(password, this.config);
  }

  async evaluateRotationOutcome(
    plainPassword: string,
    userId: string,
    comparator: PasswordHistoryComparator,
  ): Promise<PasswordRotationValidationOutcome> {
    const normalizedPlainPassword = normalizePasswordInput(
      plainPassword,
      this.config,
    );

    if (this.config.blockSubstringsFromPreviousSecrets) {
      const previousSubstrings =
        await this.config.persistence.getPreviousPasswordSubstrings?.(userId);

      if (
        hasBlockedPreviousSecretSubstring(
          normalizedPlainPassword,
          previousSubstrings,
          this.config,
        )
      ) {
        void emitAuditEvent(this.config.auditEventCallback, {
          type: "rotation",
          userId,
          outcome: "fail",
          details: {
            mode: "previousSubstring",
            historyLimit: this.config.historyLimit,
          },
        });

        return {
          valid: false,
          reason: "PASSWORD_CONTAINS_PREVIOUS_SUBSTRING",
          details: {
            minPreviousSecretSubstringLength:
              this.config.minPreviousSecretSubstringLength,
          },
        };
      }
    }

    const history = await this.config.persistence.getPasswordHistory(userId);
    const limitedHistory = history.slice(0, this.config.historyLimit);

    if (!isPasswordCompareFn(comparator)) {
      const isReused = await comparator.isReused({
        userId,
        plainPassword,
        normalizedPassword: normalizedPlainPassword,
        history: limitedHistory,
        historyLimit: this.config.historyLimit,
      });

      if (isReused) {
        void emitAuditEvent(this.config.auditEventCallback, {
          type: "rotation",
          userId,
          outcome: "fail",
          details: {
            mode: "strategy",
            historyLimit: this.config.historyLimit,
          },
        });

        return {
          valid: false,
          reason: "PASSWORD_REUSED",
          details: {
            mode: "strategy",
            historyLimit: this.config.historyLimit,
          },
        };
      }

      void emitAuditEvent(this.config.auditEventCallback, {
        type: "rotation",
        userId,
        outcome: "pass",
        details: {
          mode: "strategy",
          historyLimit: this.config.historyLimit,
        },
      });

      return { valid: true };
    }

    for (const previousHash of limitedHistory) {
      const isReused = await comparator(normalizedPlainPassword, previousHash);
      if (isReused) {
        void emitAuditEvent(this.config.auditEventCallback, {
          type: "rotation",
          userId,
          outcome: "fail",
          details: {
            mode: "compareFn",
            historyLimit: this.config.historyLimit,
          },
        });

        return {
          valid: false,
          reason: "PASSWORD_REUSED",
          details: {
            mode: "compareFn",
            historyLimit: this.config.historyLimit,
          },
        };
      }
    }

    void emitAuditEvent(this.config.auditEventCallback, {
      type: "rotation",
      userId,
      outcome: "pass",
      details: {
        mode: "compareFn",
        historyLimit: this.config.historyLimit,
      },
    });

    return { valid: true };
  }

  async validateRotation(
    plainPassword: string,
    userId: string,
    comparator: PasswordHistoryComparator,
  ): Promise<boolean> {
    const outcome = await this.evaluateRotationOutcome(
      plainPassword,
      userId,
      comparator,
    );

    return outcome.valid;
  }

  isPasswordExpired(passwordCreatedAt: PasswordCreatedAtInput): boolean {
    const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
    const now = Date.now();
    const ageInMs = now - createdAt.getTime();
    const maxAgeInMs = this.config.expiryDays * MS_PER_DAY;

    const expired = ageInMs >= maxAgeInMs;

    void emitAuditEvent(this.config.auditEventCallback, {
      type: "expiry",
      outcome: expired ? "fail" : "pass",
      details: {
        expiryDays: this.config.expiryDays,
      },
    });

    return expired;
  }

  daysUntilExpiry(passwordCreatedAt: PasswordCreatedAtInput): number {
    const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
    const now = Date.now();
    const ageInMs = now - createdAt.getTime();
    const maxAgeInMs = this.config.expiryDays * MS_PER_DAY;
    const remainingMs = maxAgeInMs - ageInMs;

    if (remainingMs <= 0) {
      return 0;
    }

    const days = Math.ceil(remainingMs / MS_PER_DAY);

    void emitAuditEvent(this.config.auditEventCallback, {
      type: "expiry",
      outcome: "info",
      details: {
        mode: "daysUntilExpiry",
        days,
      },
    });

    return days;
  }

  evaluateExpiryState(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): PasswordExpiryStateResult {
    const daysUntilExpiry = this.daysUntilExpiry(passwordCreatedAt);
    const daysRemainingInGracePeriod =
      this.daysRemainingInGracePeriod(passwordCreatedAt);

    if (daysRemainingInGracePeriod > 0) {
      const result: PasswordExpiryStateResult = {
        state: "grace",
        daysUntilExpiry,
        daysRemainingInGracePeriod,
      };

      void emitAuditEvent(this.config.auditEventCallback, {
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

    if (this.isPasswordExpired(passwordCreatedAt)) {
      const result: PasswordExpiryStateResult = {
        state: "expired",
        daysUntilExpiry,
        daysRemainingInGracePeriod,
      };

      void emitAuditEvent(this.config.auditEventCallback, {
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

    if (
      this.config.expiryWarningDays > 0 &&
      daysUntilExpiry <= this.config.expiryWarningDays
    ) {
      const result: PasswordExpiryStateResult = {
        state: "warning",
        daysUntilExpiry,
        daysRemainingInGracePeriod,
      };

      void emitAuditEvent(this.config.auditEventCallback, {
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

    void emitAuditEvent(this.config.auditEventCallback, {
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

  isWithinGracePeriod(passwordCreatedAt: PasswordCreatedAtInput): boolean {
    if (
      this.config.gracePeriodDays === 0 ||
      !this.isPasswordExpired(passwordCreatedAt)
    ) {
      return false;
    }

    const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
    const now = Date.now();
    const ageInMs = now - createdAt.getTime();
    const maxAgeInMs = this.config.expiryDays * MS_PER_DAY;
    const graceWindowInMs = this.config.gracePeriodDays * MS_PER_DAY;
    const elapsedSinceExpiryInMs = ageInMs - maxAgeInMs;

    return elapsedSinceExpiryInMs <= graceWindowInMs;
  }

  daysRemainingInGracePeriod(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): number {
    if (!this.isWithinGracePeriod(passwordCreatedAt)) {
      return 0;
    }

    const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
    const now = Date.now();
    const ageInMs = now - createdAt.getTime();
    const maxAgeInMs = this.config.expiryDays * MS_PER_DAY;
    const graceWindowInMs = this.config.gracePeriodDays * MS_PER_DAY;
    const remainingGraceInMs = maxAgeInMs + graceWindowInMs - ageInMs;

    if (remainingGraceInMs <= 0) {
      return 0;
    }

    return Math.ceil(remainingGraceInMs / MS_PER_DAY);
  }

  isMinimumPasswordAgeSatisfied(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): boolean {
    if (this.config.minimumPasswordAgeDays === 0) {
      return true;
    }

    const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
    const now = Date.now();
    const ageInMs = now - createdAt.getTime();
    const minimumAgeInMs = this.config.minimumPasswordAgeDays * MS_PER_DAY;

    const satisfied = ageInMs >= minimumAgeInMs;

    void emitAuditEvent(this.config.auditEventCallback, {
      type: "minimumPasswordAge",
      outcome: satisfied ? "pass" : "fail",
      details: {
        minimumPasswordAgeDays: this.config.minimumPasswordAgeDays,
      },
    });

    return satisfied;
  }

  evaluateMinimumPasswordAgeOutcome(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): MinimumPasswordAgeValidationOutcome {
    if (this.isMinimumPasswordAgeSatisfied(passwordCreatedAt)) {
      return { valid: true };
    }

    return {
      valid: false,
      reason: "MINIMUM_PASSWORD_AGE_NOT_SATISFIED",
      details: {
        minimumPasswordAgeDays: this.config.minimumPasswordAgeDays,
      },
    };
  }

  evaluatePasswordExpiryDecision(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): PasswordExpiryValidationOutcome {
    if (this.isPasswordExpired(passwordCreatedAt)) {
      return { valid: false, reason: "PASSWORD_EXPIRED" };
    }

    return { valid: true };
  }

  evaluateMinimumPasswordAgeDecision(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): MinimumPasswordAgeValidationOutcome {
    return this.evaluateMinimumPasswordAgeOutcome(passwordCreatedAt);
  }
}

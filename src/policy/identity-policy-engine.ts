import type {
  ComplexityValidationResult,
  IdentityPolicyEngineOptions,
  MinimumPasswordAgeValidationOutcome,
  PasswordCompromisedPasswordValidationResult,
  PasswordComplexityValidationOutcome,
  PasswordCreatedAtInput,
  PasswordExpiryStateResult,
  PasswordHistoryComparator,
  PasswordRotationValidationOutcome,
  PasswordValidationIssue,
  PasswordValidationIssueCode,
  ResolvedIdentityPolicyEngineOptions,
} from "../types/interfaces.js";
import { emitAuditEvent } from "../internal/audit.js";
import {
  hasBlockedPreviousSecretSubstring,
  hasRepeatedChars,
  hasSequentialChars,
  isInDenyList,
  isPasswordCompareFn,
  MS_PER_DAY,
  normalizePasswordCreatedAt,
  normalizePasswordInput,
  resolveEngineOptions,
} from "./engine.js";

export class IdentityPolicyEngine {
  private readonly config: ResolvedIdentityPolicyEngineOptions;

  constructor(options: IdentityPolicyEngineOptions) {
    this.config = resolveEngineOptions(options);
  }

  getConfig(): Readonly<ResolvedIdentityPolicyEngineOptions> {
    return this.config;
  }

  validateComplexity(password: string): ComplexityValidationResult {
    const errors: string[] = [];
    const issues: PasswordValidationIssue[] = [];
    const normalizedPassword = normalizePasswordInput(password, this.config);
    const addIssue = (
      code: PasswordValidationIssueCode,
      message: string,
      meta?: Record<string, unknown>,
    ): void => {
      errors.push(message);
      issues.push({ code, message, ...(meta ? { meta } : {}) });
    };

    if (normalizedPassword.length < this.config.minLength) {
      addIssue(
        "PASSWORD_TOO_SHORT",
        `Password must be at least ${this.config.minLength} characters long.`,
        {
          actualLength: normalizedPassword.length,
          requiredMinLength: this.config.minLength,
        },
      );
    }

    if (normalizedPassword.length > this.config.maxLength) {
      addIssue(
        "PASSWORD_TOO_LONG",
        `Password must be at most ${this.config.maxLength} characters long.`,
        {
          actualLength: normalizedPassword.length,
          requiredMaxLength: this.config.maxLength,
        },
      );
    }

    if (this.config.requireUppercase && !/[A-Z]/.test(normalizedPassword)) {
      addIssue(
        "PASSWORD_MISSING_UPPERCASE",
        "Password must include at least one uppercase letter.",
        {
          required: true,
          pattern: "[A-Z]",
        },
      );
    }

    if (this.config.requireLowercase && !/[a-z]/.test(normalizedPassword)) {
      addIssue(
        "PASSWORD_MISSING_LOWERCASE",
        "Password must include at least one lowercase letter.",
        {
          required: true,
          pattern: "[a-z]",
        },
      );
    }

    if (this.config.requireNumbers && !/[0-9]/.test(normalizedPassword)) {
      addIssue(
        "PASSWORD_MISSING_NUMBER",
        "Password must include at least one number.",
        {
          required: true,
          pattern: "[0-9]",
        },
      );
    }

    if (
      this.config.requireSymbols &&
      !/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(normalizedPassword)
    ) {
      addIssue(
        "PASSWORD_MISSING_SYMBOL",
        "Password must include at least one symbol.",
        {
          required: true,
          pattern: "[symbol]",
        },
      );
    }

    if (isInDenyList(normalizedPassword, this.config.denyList, this.config)) {
      addIssue(
        "PASSWORD_DENY_LISTED_PATTERN",
        "Password contains a denied pattern.",
        {
          denyListSize: this.config.denyList.length,
        },
      );
    }

    if (
      this.config.preventRepeatedChars &&
      hasRepeatedChars(normalizedPassword, this.config.maxRepeatedChars)
    ) {
      addIssue(
        "PASSWORD_REPEATED_CONSECUTIVE_CHARS",
        `Password must not contain more than ${this.config.maxRepeatedChars} repeated consecutive characters.`,
        {
          maxRepeatedChars: this.config.maxRepeatedChars,
        },
      );
    }

    if (
      this.config.preventSequentialChars &&
      hasSequentialChars(normalizedPassword, this.config.maxSequentialChars)
    ) {
      addIssue(
        "PASSWORD_SEQUENTIAL_CHAR_RUN",
        `Password must not contain sequential character runs of length ${this.config.maxSequentialChars} or more.`,
        {
          maxSequentialChars: this.config.maxSequentialChars,
        },
      );
    }

    const result = {
      isValid: errors.length === 0,
      errors,
      ...(issues.length > 0 ? { issues } : {}),
    };

    void emitAuditEvent(this.config.auditEventCallback, {
      type: "complexity",
      outcome: result.isValid ? "pass" : "fail",
      details: {
        errorCount: result.errors.length,
        minLength: this.config.minLength,
        maxLength: this.config.maxLength,
      },
    });

    return result;
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
    const baseResult = this.validateComplexity(password);
    const errors = [...baseResult.errors];
    const issues: PasswordValidationIssue[] = [...(baseResult.issues ?? [])];
    const normalizedPassword = normalizePasswordInput(password, this.config);
    const addIssue = (
      code: PasswordValidationIssueCode,
      message: string,
      meta?: Record<string, unknown>,
    ): void => {
      errors.push(message);
      issues.push({ code, message, ...(meta ? { meta } : {}) });
    };

    if (this.config.entropyValidator) {
      const entropyResult = await this.config.entropyValidator({
        password,
        normalizedPassword,
      });

      if (!entropyResult.isValid) {
        addIssue(
          "PASSWORD_ENTROPY_TOO_LOW",
          "Password entropy score is below the configured minimum.",
          {
            score: entropyResult.score,
            ...(entropyResult.details ?? {}),
          },
        );
      }
    }

    if (this.config.compromisedPasswordValidator) {
      const rawResult = await this.config.compromisedPasswordValidator({
        password,
        normalizedPassword,
      });
      const compromisedResult: PasswordCompromisedPasswordValidationResult =
        typeof rawResult === "boolean"
          ? { isCompromised: rawResult }
          : rawResult;

      if (compromisedResult.isCompromised) {
        addIssue(
          "PASSWORD_COMPROMISED",
          "Password appears in compromised password sources.",
          compromisedResult.details,
        );
      }
    }

    const result = {
      isValid: errors.length === 0,
      errors,
      ...(issues.length > 0 ? { issues } : {}),
    };

    void emitAuditEvent(this.config.auditEventCallback, {
      type: "complexity",
      outcome: result.isValid ? "pass" : "fail",
      details: {
        mode: "extended",
        errorCount: result.errors.length,
      },
    });

    return result;
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
}

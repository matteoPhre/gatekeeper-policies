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
import { emitDeprecationWarning } from "../internal/deprecation.js";
import { resolveEngineOptions } from "./engine.js";
import {
  validateLegacyComplexity,
  validateLegacyComplexityWithExtensions,
} from "./legacy-complexity.js";
import {
  daysRemainingInGracePeriodLegacy,
  daysUntilExpiryLegacy,
  evaluateLegacyExpiryState,
  evaluateLegacyRotationOutcome,
  evaluateMinimumPasswordAgeDecisionLegacy,
  evaluateMinimumPasswordAgeOutcomeLegacy,
  evaluatePasswordExpiryDecisionLegacy,
  isMinimumPasswordAgeSatisfiedLegacy,
  isPasswordExpiredLegacy,
  isWithinGracePeriodLegacy,
} from "./legacy-rotation-expiry.js";

export class IdentityPolicyEngine {
  private readonly config: ResolvedIdentityPolicyEngineOptions;

  constructor(options: IdentityPolicyEngineOptions) {
    this.config = resolveEngineOptions(options);
  }

  getConfig(): Readonly<ResolvedIdentityPolicyEngineOptions> {
    return this.config;
  }

  /**
   * @deprecated Use evaluateComplexityOutcome for typed decision results.
   * Planned removal: v2.0.0.
   */
  validateComplexity(password: string): ComplexityValidationResult {
    emitDeprecationWarning(
      this.config.deprecationWarnings,
      "validateComplexity",
      "evaluateComplexityOutcome",
      "v2.0.0",
    );

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
    return evaluateLegacyRotationOutcome(
      plainPassword,
      userId,
      comparator,
      this.config,
    );
  }

  /**
   * @deprecated Use evaluateRotationOutcome for typed decision results.
   * Planned removal: v2.0.0.
   */
  async validateRotation(
    plainPassword: string,
    userId: string,
    comparator: PasswordHistoryComparator,
  ): Promise<boolean> {
    emitDeprecationWarning(
      this.config.deprecationWarnings,
      "validateRotation",
      "evaluateRotationOutcome",
      "v2.0.0",
    );

    const outcome = await this.evaluateRotationOutcome(
      plainPassword,
      userId,
      comparator,
    );

    return outcome.valid;
  }

  /**
   * @deprecated Use evaluatePasswordExpiryDecision for typed decision results.
   * Planned removal: v2.0.0.
   */
  isPasswordExpired(passwordCreatedAt: PasswordCreatedAtInput): boolean {
    emitDeprecationWarning(
      this.config.deprecationWarnings,
      "isPasswordExpired",
      "evaluatePasswordExpiryDecision",
      "v2.0.0",
    );

    return isPasswordExpiredLegacy(passwordCreatedAt, this.config);
  }

  /**
   * @deprecated Use evaluateExpiryState for typed lifecycle results.
   * Planned removal: v2.0.0.
   */
  daysUntilExpiry(passwordCreatedAt: PasswordCreatedAtInput): number {
    emitDeprecationWarning(
      this.config.deprecationWarnings,
      "daysUntilExpiry",
      "evaluateExpiryState",
      "v2.0.0",
    );

    return daysUntilExpiryLegacy(passwordCreatedAt, this.config);
  }

  evaluateExpiryState(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): PasswordExpiryStateResult {
    return evaluateLegacyExpiryState(passwordCreatedAt, this.config);
  }

  /**
   * @deprecated Use evaluateExpiryState for typed lifecycle results.
   * Planned removal: v2.0.0.
   */
  isWithinGracePeriod(passwordCreatedAt: PasswordCreatedAtInput): boolean {
    emitDeprecationWarning(
      this.config.deprecationWarnings,
      "isWithinGracePeriod",
      "evaluateExpiryState",
      "v2.0.0",
    );

    return isWithinGracePeriodLegacy(passwordCreatedAt, this.config);
  }

  /**
   * @deprecated Use evaluateExpiryState for typed lifecycle results.
   * Planned removal: v2.0.0.
   */
  daysRemainingInGracePeriod(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): number {
    emitDeprecationWarning(
      this.config.deprecationWarnings,
      "daysRemainingInGracePeriod",
      "evaluateExpiryState",
      "v2.0.0",
    );

    return daysRemainingInGracePeriodLegacy(passwordCreatedAt, this.config);
  }

  /**
   * @deprecated Use evaluateMinimumPasswordAgeDecision for typed decision results.
   * Planned removal: v2.0.0.
   */
  isMinimumPasswordAgeSatisfied(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): boolean {
    emitDeprecationWarning(
      this.config.deprecationWarnings,
      "isMinimumPasswordAgeSatisfied",
      "evaluateMinimumPasswordAgeDecision",
      "v2.0.0",
    );

    return isMinimumPasswordAgeSatisfiedLegacy(passwordCreatedAt, this.config);
  }

  evaluateMinimumPasswordAgeOutcome(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): MinimumPasswordAgeValidationOutcome {
    return evaluateMinimumPasswordAgeOutcomeLegacy(passwordCreatedAt, this.config);
  }

  evaluatePasswordExpiryDecision(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): PasswordExpiryValidationOutcome {
    return evaluatePasswordExpiryDecisionLegacy(passwordCreatedAt, this.config);
  }

  evaluateMinimumPasswordAgeDecision(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): MinimumPasswordAgeValidationOutcome {
    return evaluateMinimumPasswordAgeDecisionLegacy(passwordCreatedAt, this.config);
  }
}

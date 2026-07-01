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
    return evaluateLegacyRotationOutcome(
      plainPassword,
      userId,
      comparator,
      this.config,
    );
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
    return isPasswordExpiredLegacy(passwordCreatedAt, this.config);
  }

  daysUntilExpiry(passwordCreatedAt: PasswordCreatedAtInput): number {
    return daysUntilExpiryLegacy(passwordCreatedAt, this.config);
  }

  evaluateExpiryState(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): PasswordExpiryStateResult {
    return evaluateLegacyExpiryState(passwordCreatedAt, this.config);
  }

  isWithinGracePeriod(passwordCreatedAt: PasswordCreatedAtInput): boolean {
    return isWithinGracePeriodLegacy(passwordCreatedAt, this.config);
  }

  daysRemainingInGracePeriod(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): number {
    return daysRemainingInGracePeriodLegacy(passwordCreatedAt, this.config);
  }

  isMinimumPasswordAgeSatisfied(
    passwordCreatedAt: PasswordCreatedAtInput,
  ): boolean {
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

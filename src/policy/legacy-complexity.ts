import type {
  ComplexityValidationResult,
  PasswordCompromisedPasswordValidationResult,
  PasswordValidationIssue,
  PasswordValidationIssueCode,
  ResolvedIdentityPolicyEngineOptions,
} from "../types/interfaces.js";
import { emitAuditEvent } from "../internal/audit.js";
import {
  hasRepeatedChars,
  hasSequentialChars,
  isInDenyList,
  normalizePasswordInput,
} from "./engine.js";

export function validateLegacyComplexity(
  password: string,
  config: ResolvedIdentityPolicyEngineOptions,
): ComplexityValidationResult {
  const errors: string[] = [];
  const issues: PasswordValidationIssue[] = [];
  const normalizedPassword = normalizePasswordInput(password, config);
  const addIssue = (
    code: PasswordValidationIssueCode,
    message: string,
    meta?: Record<string, unknown>,
  ): void => {
    errors.push(message);
    issues.push({ code, message, ...(meta ? { meta } : {}) });
  };

  if (normalizedPassword.length < config.minLength) {
    addIssue(
      "PASSWORD_TOO_SHORT",
      `Password must be at least ${config.minLength} characters long.`,
      {
        actualLength: normalizedPassword.length,
        requiredMinLength: config.minLength,
      },
    );
  }

  if (normalizedPassword.length > config.maxLength) {
    addIssue(
      "PASSWORD_TOO_LONG",
      `Password must be at most ${config.maxLength} characters long.`,
      {
        actualLength: normalizedPassword.length,
        requiredMaxLength: config.maxLength,
      },
    );
  }

  if (config.requireUppercase && !/[A-Z]/.test(normalizedPassword)) {
    addIssue(
      "PASSWORD_MISSING_UPPERCASE",
      "Password must include at least one uppercase letter.",
      {
        required: true,
        pattern: "[A-Z]",
      },
    );
  }

  if (config.requireLowercase && !/[a-z]/.test(normalizedPassword)) {
    addIssue(
      "PASSWORD_MISSING_LOWERCASE",
      "Password must include at least one lowercase letter.",
      {
        required: true,
        pattern: "[a-z]",
      },
    );
  }

  if (config.requireNumbers && !/[0-9]/.test(normalizedPassword)) {
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
    config.requireSymbols &&
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

  if (isInDenyList(normalizedPassword, config.denyList, config)) {
    addIssue(
      "PASSWORD_DENY_LISTED_PATTERN",
      "Password contains a denied pattern.",
      {
        denyListSize: config.denyList.length,
      },
    );
  }

  if (config.preventRepeatedChars && hasRepeatedChars(normalizedPassword, config.maxRepeatedChars)) {
    addIssue(
      "PASSWORD_REPEATED_CONSECUTIVE_CHARS",
      `Password must not contain more than ${config.maxRepeatedChars} repeated consecutive characters.`,
      {
        maxRepeatedChars: config.maxRepeatedChars,
      },
    );
  }

  if (config.preventSequentialChars && hasSequentialChars(normalizedPassword, config.maxSequentialChars)) {
    addIssue(
      "PASSWORD_SEQUENTIAL_CHAR_RUN",
      `Password must not contain sequential character runs of length ${config.maxSequentialChars} or more.`,
      {
        maxSequentialChars: config.maxSequentialChars,
      },
    );
  }

  const result = {
    isValid: errors.length === 0,
    errors,
    ...(issues.length > 0 ? { issues } : {}),
  };

  void emitAuditEvent(config.auditEventCallback, {
    type: "complexity",
    outcome: result.isValid ? "pass" : "fail",
    details: {
      errorCount: result.errors.length,
      minLength: config.minLength,
      maxLength: config.maxLength,
    },
  });

  return result;
}

export async function validateLegacyComplexityWithExtensions(
  password: string,
  config: ResolvedIdentityPolicyEngineOptions,
): Promise<ComplexityValidationResult> {
  const baseResult = validateLegacyComplexity(password, config);
  const errors = [...baseResult.errors];
  const issues: PasswordValidationIssue[] = [...(baseResult.issues ?? [])];
  const normalizedPassword = normalizePasswordInput(password, config);
  const addIssue = (
    code: PasswordValidationIssueCode,
    message: string,
    meta?: Record<string, unknown>,
  ): void => {
    errors.push(message);
    issues.push({ code, message, ...(meta ? { meta } : {}) });
  };

  if (config.entropyValidator) {
    const entropyResult = await config.entropyValidator({
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

  if (config.compromisedPasswordValidator) {
    const rawResult = await config.compromisedPasswordValidator({
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

  void emitAuditEvent(config.auditEventCallback, {
    type: "complexity",
    outcome: result.isValid ? "pass" : "fail",
    details: {
      mode: "extended",
      errorCount: result.errors.length,
    },
  });

  return result;
}
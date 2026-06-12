import { describe, expect, it, vi } from "vitest";
import {
  constantTimeStringEqual,
  createCompromisedPasswordDictionaryValidator,
  IdentityPolicyEngine,
} from "../src";
import type { PasswordPersistenceCallbacks } from "../src/types/interfaces.js";

function createPersistenceMock(): PasswordPersistenceCallbacks {
  return {
    getPasswordHistory: vi.fn(async () => []),
    saveNewPassword: vi.fn(async () => undefined),
  };
}

describe("threat controls - reference examples", () => {
  it("tracks repeated failed complexity checks for brute-force monitoring", () => {
    const failedAttempts = new Map<string, number>();
    const engine = new IdentityPolicyEngine({
      minLength: 12,
      persistence: createPersistenceMock(),
    });

    const validateWithBruteForceTracking = (
      userId: string,
      password: string,
    ) => {
      const result = engine.validateComplexity(password);

      if (!result.isValid) {
        failedAttempts.set(userId, (failedAttempts.get(userId) ?? 0) + 1);
      }

      return result;
    };

    validateWithBruteForceTracking("user-42", "weak");
    validateWithBruteForceTracking("user-42", "also-weak");
    validateWithBruteForceTracking("user-99", "weak");

    expect(failedAttempts.get("user-42")).toBe(2);
    expect(failedAttempts.get("user-99")).toBe(1);
  });

  it("blocks credential-stuffing candidates via compromised-password validator", async () => {
    const knownBreachedPasswords = ["password123", "letmein", "qwerty2024"];
    const engine = new IdentityPolicyEngine({
      compromisedPasswordValidator:
        createCompromisedPasswordDictionaryValidator(knownBreachedPasswords),
      persistence: createPersistenceMock(),
    });

    const result = await engine.validateComplexityWithExtensions("QwErTy2024");

    expect(result.isValid).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "PASSWORD_COMPROMISED" }),
      ]),
    );
  });

  it("uses constant-time comparison for host-managed token checks", () => {
    const submittedToken = "session-token-value";
    const storedToken = "session-token-value";

    expect(constantTimeStringEqual(submittedToken, storedToken)).toBe(true);
    expect(constantTimeStringEqual(submittedToken, "session-token-valuE")).toBe(
      false,
    );
  });
});

describe("typed validation outcomes", () => {
  it("returns structured complexity outcomes", () => {
    const engine = new IdentityPolicyEngine({
      minLength: 12,
      persistence: createPersistenceMock(),
    });

    expect(engine.evaluateComplexityOutcome("StrongPassword#2026")).toEqual({
      valid: true,
    });

    const outcome = engine.evaluateComplexityOutcome("short");
    expect(outcome.valid).toBe(false);
    if (!outcome.valid) {
      expect(outcome.reasons).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ code: "PASSWORD_TOO_SHORT" }),
        ]),
      );
    }
  });

  it("returns structured rotation outcomes", async () => {
    const engine = new IdentityPolicyEngine({
      blockSubstringsFromPreviousSecrets: true,
      persistence: {
        getPasswordHistory: vi.fn(async () => []),
        saveNewPassword: vi.fn(async () => undefined),
        getPreviousPasswordSubstrings: vi.fn(async () => ["prev"]),
      },
    });

    const outcome = await engine.evaluateRotationOutcome(
      "new-prev-secret",
      "user-1",
      async () => false,
    );

    expect(outcome).toEqual({
      valid: false,
      reason: "PASSWORD_CONTAINS_PREVIOUS_SUBSTRING",
      details: {
        minPreviousSecretSubstringLength: 4,
      },
    });
  });

  it("returns structured minimum-password-age outcomes", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-11T12:00:00.000Z"));

    const engine = new IdentityPolicyEngine({
      minimumPasswordAgeDays: 7,
      persistence: createPersistenceMock(),
    });

    expect(
      engine.evaluateMinimumPasswordAgeOutcome("2026-06-10T12:00:00.000Z"),
    ).toEqual({
      valid: false,
      reason: "MINIMUM_PASSWORD_AGE_NOT_SATISFIED",
      details: {
        minimumPasswordAgeDays: 7,
      },
    });

    expect(
      engine.evaluateMinimumPasswordAgeOutcome("2026-06-01T12:00:00.000Z"),
    ).toEqual({ valid: true });

    vi.useRealTimers();
  });
});

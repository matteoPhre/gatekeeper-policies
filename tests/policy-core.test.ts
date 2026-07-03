import { describe, expect, it } from "vitest";
import {
  IdentityPolicyEngine,
  PasswordComplexityEngine,
  PasswordExpiryEngine,
  PasswordLockoutEngine,
  PasswordRotationEngine,
  type PasswordRule,
} from "../src/policy-core";
import { IdentityPolicyEngine as LegacyIdentityPolicyEngine } from "../src/policy/identity-policy-engine.js";

const baseComplexityConfig = {
  minLength: 12,
  maxLength: 128,
  normalizeTrim: false,
  normalizeUnicode: false,
  unicodeNormalizationForm: "NFKC" as const,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
  denyList: [] as string[],
  preventRepeatedChars: false,
  maxRepeatedChars: 3,
  preventSequentialChars: false,
  maxSequentialChars: 3,
};

describe("policy-core architecture", () => {
  it("returns typed decision from complexity engine", async () => {
    const complexity = new PasswordComplexityEngine(baseComplexityConfig);

    const result = await complexity.evaluate("short");

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reason).toBe("PASSWORD_TOO_SHORT");
    }
  });

  it("supports trace-enabled evaluation order", async () => {
    const traceRule: PasswordRule = async () => ({ success: true });
    const complexity = new PasswordComplexityEngine({
      ...baseComplexityConfig,
      extensionRules: [traceRule],
    });

    const result = await complexity.evaluate("StrongPassword#2026", {
      trace: true,
    });

    expect(result.success).toBe(true);
    expect(result.trace?.length).toBeGreaterThan(0);
    expect(result.trace?.[0]?.step).toBe("minLength");
  });

  it("composes engines through facade", async () => {
    const engine = new IdentityPolicyEngine({
      complexity: new PasswordComplexityEngine(baseComplexityConfig),
      rotation: new PasswordRotationEngine(
        {
          historyLimit: 5,
          blockSubstringsFromPreviousSecrets: false,
          minPreviousSecretSubstringLength: 4,
        },
        {
          getPasswordHistory: async () => ["h1"],
        },
      ),
      expiry: new PasswordExpiryEngine({ expiryDays: 90 }),
    });

    const result = await engine.validateComplexity("StrongPassword#2026");

    expect(result.success).toBe(true);
  });

  it("freezes resolved legacy config at runtime", () => {
    const engine = new LegacyIdentityPolicyEngine({
      persistence: {
        getPasswordHistory: async () => [],
        saveNewPassword: async () => undefined,
      },
      denyList: ["Password123"],
    });

    const config = engine.getConfig();

    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.denyList)).toBe(true);
  });

  it("fails closed when rotation dependencies throw", async () => {
    const rotation = new PasswordRotationEngine(
      {
        historyLimit: 5,
        blockSubstringsFromPreviousSecrets: false,
        minPreviousSecretSubstringLength: 4,
      },
      {
        getPasswordHistory: async () => {
          throw new Error("rotation history unavailable");
        },
      },
    );

    const result = await rotation.evaluate(
      "StrongPassword#2026",
      "user-1",
      async () => false,
    );

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reason).toBe("PASSWORD_REUSED");
      expect(result.meta).toEqual({ failureMode: "fail_closed" });
    }
  });

  it("fails open when rotation dependencies throw and fail-open is enabled", async () => {
    const rotation = new PasswordRotationEngine(
      {
        historyLimit: 5,
        blockSubstringsFromPreviousSecrets: false,
        minPreviousSecretSubstringLength: 4,
      },
      {
        getPasswordHistory: async () => {
          throw new Error("rotation history unavailable");
        },
      },
      {
        failureMode: "fail_open",
      },
    );

    const result = await rotation.evaluate(
      "StrongPassword#2026",
      "user-1",
      async () => false,
    );

    expect(result.success).toBe(true);
  });

  it("fails closed when expiry parsing fails", async () => {
    const expiry = new PasswordExpiryEngine({ expiryDays: 90 });

    const result = await expiry.evaluate("not-a-date");

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reason).toBe("PASSWORD_EXPIRED");
      expect(result.meta).toEqual({ failureMode: "fail_closed" });
    }
  });

  it("fails open when expiry parsing fails and fail-open is enabled", async () => {
    const expiry = new PasswordExpiryEngine(
      { expiryDays: 90 },
      { failureMode: "fail_open" },
    );

    const result = await expiry.evaluate("not-a-date");

    expect(result.success).toBe(true);
  });

  it("tracks failed attempts and returns typed lockout decision", async () => {
    const stateStore = new Map<string, { consecutiveFailures: number; lockoutUntil?: string }>();
    const lockout = new PasswordLockoutEngine(
      {
        maxFailedAttempts: 3,
        lockoutDurationMinutes: 15,
        resetOnSuccess: true,
      },
      {
        getState: async (userId) => stateStore.get(userId),
        setState: async (userId, state) => {
          stateStore.set(userId, state);
        },
      },
    );

    await lockout.evaluateAttempt("user-1", false);
    await lockout.evaluateAttempt("user-1", false);
    const thirdAttempt = await lockout.evaluateAttempt("user-1", false, {
      trace: true,
    });

    expect(thirdAttempt.success).toBe(false);
    if (!thirdAttempt.success) {
      expect(thirdAttempt.reason).toBe("ACCOUNT_TEMPORARILY_LOCKED");
      expect(thirdAttempt.meta).toEqual(
        expect.objectContaining({
          consecutiveFailures: 3,
          maxFailedAttempts: 3,
          lockoutUntil: expect.any(String),
        }),
      );
    }

    expect(thirdAttempt.trace?.some((step) => step.step === "lockoutApplied")).toBe(true);
  });

  it("resets lockout counters on success when configured", async () => {
    const stateStore = new Map<string, { consecutiveFailures: number; lockoutUntil?: string }>();
    const lockout = new PasswordLockoutEngine(
      {
        maxFailedAttempts: 4,
        lockoutDurationMinutes: 10,
        resetOnSuccess: true,
      },
      {
        getState: async (userId) => stateStore.get(userId),
        setState: async (userId, state) => {
          stateStore.set(userId, state);
        },
      },
    );

    await lockout.evaluateAttempt("user-2", false);
    await lockout.evaluateAttempt("user-2", false);
    await lockout.evaluateAttempt("user-2", true);

    expect(stateStore.get("user-2")).toEqual({ consecutiveFailures: 0 });
  });
});

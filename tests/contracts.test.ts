import { describe, expect, it, vi } from "vitest";
import {
  IdentityPolicyEngine,
  createBulkPasswordHistoryComparisonStrategy,
  createCompromisedPasswordDictionaryValidator,
  createScoreBasedEntropyValidator,
} from "../src/index.js";
import type { PasswordRule } from "../src/policy-core.js";
import { PasswordComplexityEngine } from "../src/policy-core.js";

function createPersistenceMock(history: string[] = []) {
  return {
    getPasswordHistory: vi.fn(async () => history),
    saveNewPassword: vi.fn(async () => undefined),
  };
}

describe("contract tests - extension interfaces", () => {
  it("passes normalized context into complexity extension rules", async () => {
    const observedContexts: Array<{
      password: string;
      normalizedPassword: string;
      minLength: number;
    }> = [];

    const extensionRule: PasswordRule = async (context) => {
      observedContexts.push({
        password: context.password,
        normalizedPassword: context.normalizedPassword,
        minLength: context.config.minLength,
      });

      return { success: true };
    };

    const engine = new PasswordComplexityEngine({
      minLength: 1,
      maxLength: 128,
      normalizeTrim: true,
      normalizeUnicode: true,
      unicodeNormalizationForm: "NFC",
      requireUppercase: false,
      requireLowercase: false,
      requireNumbers: false,
      requireSymbols: false,
      denyList: [],
      preventRepeatedChars: false,
      maxRepeatedChars: 3,
      preventSequentialChars: false,
      maxSequentialChars: 3,
      extensionRules: [extensionRule],
    });

    const result = await engine.evaluate("  cafe\u0301  ");

    expect(result.success).toBe(true);
    expect(observedContexts).toEqual([
      {
        password: "  cafe\u0301  ",
        normalizedPassword: "café",
        minLength: 1,
      },
    ]);
  });

  it("adapts bulk history comparison callbacks with the expected contract", async () => {
    const compareFn = vi.fn(async (normalizedPassword, history, context) => {
      expect(normalizedPassword).toBe("candidate");
      expect(history).toEqual(["h1", "h2"]);
      expect(context).toEqual({
        userId: "user-1",
        plainPassword: "  candidate  ",
        historyLimit: 2,
      });

      return false;
    });

    const engine = new IdentityPolicyEngine({
      historyLimit: 2,
      normalizeTrim: true,
      persistence: createPersistenceMock(["h1", "h2", "h3"]),
    });

    const comparator = createBulkPasswordHistoryComparisonStrategy(compareFn);
    const allowed = await engine.validateRotation(
      "  candidate  ",
      "user-1",
      comparator,
    );

    expect(allowed).toBe(true);
    expect(compareFn).toHaveBeenCalledTimes(1);
  });

  it("keeps intrinsic validators host-managed and deterministic", async () => {
    const entropyValidator = createScoreBasedEntropyValidator(async (password) => {
      expect(password).toBe("candidate");
      return password.length;
    }, 9);

    const compromisedValidator = createCompromisedPasswordDictionaryValidator([
      "candidate",
      "other",
    ]);

    await expect(
      entropyValidator({ password: "candidate", normalizedPassword: "candidate" }),
    ).resolves.toEqual({
      isValid: true,
      score: 9,
      details: { minimumScore: 9 },
    });

    expect(
      compromisedValidator({
        password: "candidate",
        normalizedPassword: " candidate ",
      }),
    ).toEqual({
      isCompromised: true,
      details: { dictionarySize: 2 },
    });
  });
});
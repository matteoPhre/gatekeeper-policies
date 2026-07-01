import { describe, expect, it, vi } from "vitest";
import {
  PasswordComplexityEngine,
  PasswordExpiryEngine,
  PasswordRotationEngine,
} from "../src/policy-core.js";

const complexityConfig = {
  minLength: 12,
  maxLength: 128,
  normalizeTrim: true,
  normalizeUnicode: true,
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

function createRotationDependencies() {
  return {
    getPasswordHistory: vi.fn(async () => ["h1", "h2"]),
    getPreviousPasswordSubstrings: vi.fn(async () => []),
  };
}

describe("determinism verification", () => {
  it("returns the same complexity decision for the same input", async () => {
    const engine = new PasswordComplexityEngine(complexityConfig);

    const first = await engine.evaluate("StrongPassword#2026");
    const second = await engine.evaluate("StrongPassword#2026");

    expect(second).toEqual(first);
  });

  it("returns the same rotation decision for the same input", async () => {
    const dependencies = createRotationDependencies();
    const engine = new PasswordRotationEngine(
      {
        historyLimit: 2,
        blockSubstringsFromPreviousSecrets: false,
        minPreviousSecretSubstringLength: 4,
      },
      dependencies,
    );

    const comparator = vi.fn(async () => false);

    const first = await engine.evaluate(
      "StrongPassword#2026",
      "user-1",
      comparator,
    );
    const second = await engine.evaluate(
      "StrongPassword#2026",
      "user-1",
      comparator,
    );

    expect(second).toEqual(first);
    expect(dependencies.getPasswordHistory).toHaveBeenCalledTimes(2);
    expect(comparator).toHaveBeenCalledTimes(4);
  });

  it("returns the same expiry decision for the same input with a fixed clock", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

    const engine = new PasswordExpiryEngine({ expiryDays: 90 });

    const first = await engine.evaluate("2026-03-08T00:00:00.000Z");
    const second = await engine.evaluate("2026-03-08T00:00:00.000Z");

    expect(second).toEqual(first);

    vi.useRealTimers();
  });
});
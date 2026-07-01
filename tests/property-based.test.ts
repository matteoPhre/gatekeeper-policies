import { describe, expect, it, vi } from "vitest";
import {
  PasswordComplexityEngine,
  PasswordExpiryEngine,
  PasswordRotationEngine,
} from "../src/policy-core.js";

const MS_PER_DAY = 24 * 60 * 60 * 1000;

const complexityConfig = {
  minLength: 12,
  maxLength: 128,
  normalizeTrim: true,
  normalizeUnicode: true,
  unicodeNormalizationForm: "NFKC" as const,
  requireUppercase: true,
  requireLowercase: false,
  requireNumbers: true,
  requireSymbols: true,
  denyList: [] as string[],
  preventRepeatedChars: false,
  maxRepeatedChars: 3,
  preventSequentialChars: false,
  maxSequentialChars: 3,
};

function createSeededRandom(seed: number): () => number {
  let state = seed >>> 0;

  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function randomInt(random: () => number, min: number, max: number): number {
  return Math.floor(random() * (max - min + 1)) + min;
}

function buildStrongCandidate(length: number): string {
  return "A1!".repeat(Math.ceil(length / 3)).slice(0, length);
}

function buildToken(random: () => number, prefix: string): string {
  return `${prefix}-${randomInt(random, 1000, 9999)}-${randomInt(random, 1000, 9999)}`;
}

function createRotationDependencies(history: string[]) {
  return {
    getPasswordHistory: vi.fn(async () => history),
    getPreviousPasswordSubstrings: vi.fn(async () => []),
  };
}

describe("property-based quality gates", () => {
  it("keeps complexity evaluation aligned with length boundaries across generated cases", async () => {
    const engine = new PasswordComplexityEngine(complexityConfig);
    const random = createSeededRandom(0x1a2b3c4d);

    for (let index = 0; index < 40; index += 1) {
      const length = randomInt(random, 1, 24);
      const candidate = buildStrongCandidate(length);

      const first = await engine.evaluate(candidate);
      const second = await engine.evaluate(candidate);

      expect(second).toEqual(first);

      if (length < complexityConfig.minLength) {
        expect(first.success).toBe(false);
        if (!first.success) {
          expect(first.reason).toBe("PASSWORD_TOO_SHORT");
        }
        continue;
      }

      expect(first.success).toBe(true);
    }
  });

  it("keeps rotation decisions consistent across generated history sets", async () => {
    const random = createSeededRandom(0x5a17c0de);

    for (let index = 0; index < 24; index += 1) {
      const candidate = buildToken(random, `candidate-${index}`);
      const historySize = randomInt(random, 0, 5);
      const history = Array.from({ length: historySize }, (_, historyIndex) =>
        buildToken(random, `history-${index}-${historyIndex}`),
      );
      const injectMatch = history.length > 0 && random() > 0.5;
      let expectedCalls = history.length;

      if (injectMatch) {
        const matchIndex = randomInt(random, 0, history.length - 1);
        history[matchIndex] = candidate;
        expectedCalls = matchIndex + 1;
      }

      const engine = new PasswordRotationEngine(
        {
          historyLimit: 5,
          blockSubstringsFromPreviousSecrets: false,
          minPreviousSecretSubstringLength: 4,
        },
        createRotationDependencies(history),
      );

      const comparator = vi.fn(async (_plain: string | Uint8Array, previousHash) =>
        previousHash === candidate,
      );

      const result = await engine.evaluate(candidate, `user-${index}`, comparator);

      expect(result.success).toBe(!injectMatch);
      expect(comparator.mock.calls.length).toBe(expectedCalls);
    }
  });

  it("keeps expiry decisions aligned with age thresholds across generated dates", async () => {
    const random = createSeededRandom(0x7e57cafe);
    const now = new Date("2026-06-05T00:00:00.000Z");

    vi.useFakeTimers();
    vi.setSystemTime(now);

    try {
      const engine = new PasswordExpiryEngine({ expiryDays: 90 });

      for (let index = 0; index < 32; index += 1) {
        const ageDays = randomInt(random, 0, 120);
        const createdAt = new Date(now.getTime() - ageDays * MS_PER_DAY);
        const expectedExpired = ageDays >= 90;

        const first = await engine.evaluate(createdAt.toISOString());
        const second = await engine.evaluate(createdAt);

        expect(second).toEqual(first);
        expect(first.success).toBe(!expectedExpired);
      }
    } finally {
      vi.useRealTimers();
    }
  });
});
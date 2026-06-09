import { describe, expect, it, vi } from "vitest";
import {
    createBulkPasswordHistoryComparisonStrategy,
    IdentityPolicyEngine,
    normalizePasswordCreatedAt,
} from "../src/engine";
import type { PasswordPersistenceCallbacks } from "../src/interfaces";

function createPersistenceMock(
    history: string[] = [],
    previousSubstrings?: string[],
): PasswordPersistenceCallbacks {
    return {
        getPasswordHistory: vi.fn(async () => history),
        saveNewPassword: vi.fn(async () => undefined),
        getPreviousPasswordSubstrings: vi.fn(async () => previousSubstrings ?? []),
    };
}

describe("IdentityPolicyEngine - complexity", () => {
    it("rejects weak password with detailed errors", () => {
        const engine = new IdentityPolicyEngine({
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("short");

        expect(result.isValid).toBe(false);
        expect(result.errors).toEqual([
            "Password must be at least 12 characters long.",
            "Password must include at least one uppercase letter.",
            "Password must include at least one number.",
            "Password must include at least one symbol.",
        ]);
    });

    it("accepts password that satisfies default policy", () => {
        const engine = new IdentityPolicyEngine({
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("StrongPassword#2026");

        expect(result).toEqual({ isValid: true, errors: [] });
    });

    it("supports custom relaxed policy", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 6,
            requireUppercase: false,
            requireNumbers: false,
            requireSymbols: false,
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("abcdef");

        expect(result).toEqual({ isValid: true, errors: [] });
    });

    it("rejects password when maxLength is exceeded", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 3,
            maxLength: 5,
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSymbols: false,
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("123456");

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain("Password must be at most 5 characters long.");
    });

    it("enforces lowercase when required", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 3,
            maxLength: 50,
            requireUppercase: false,
            requireLowercase: true,
            requireNumbers: false,
            requireSymbols: false,
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("ABC123");

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain("Password must include at least one lowercase letter.");
    });

    it("blocks deny-listed patterns (case-insensitive)", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 3,
            maxLength: 50,
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSymbols: false,
            denyList: ["password", "qwerty"],
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("MyPassWORD2026");

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain("Password contains a denied pattern.");
    });

    it("blocks repeated consecutive characters when enabled", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 3,
            maxLength: 50,
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSymbols: false,
            preventRepeatedChars: true,
            maxRepeatedChars: 2,
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("A111B");

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
            "Password must not contain more than 2 repeated consecutive characters.",
        );
    });

    it("blocks sequential runs when enabled", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 3,
            maxLength: 50,
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSymbols: false,
            preventSequentialChars: true,
            maxSequentialChars: 4,
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("abCD1234!");

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain(
            "Password must not contain sequential character runs of length 4 or more.",
        );
    });

    it("applies trim normalization before evaluating maxLength", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 3,
            maxLength: 5,
            normalizeTrim: true,
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSymbols: false,
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("  abc  ");

        expect(result).toEqual({ isValid: true, errors: [] });
    });

    it("applies unicode normalization before deny-list matching", () => {
        const engine = new IdentityPolicyEngine({
            minLength: 3,
            maxLength: 50,
            normalizeUnicode: true,
            unicodeNormalizationForm: "NFC",
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSymbols: false,
            denyList: ["cafe\u0301"],
            persistence: createPersistenceMock(),
        });

        const result = engine.validateComplexity("CAFÉ2026");

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain("Password contains a denied pattern.");
    });
});

describe("IdentityPolicyEngine - rotation", () => {
    it("blocks password reuse when compare function matches history hash", async () => {
        const engine = new IdentityPolicyEngine({
            persistence: createPersistenceMock(["h1", "h2", "h3"]),
        });

        const compareFn = vi.fn(async (_plain: string | Uint8Array, encrypted: string) => encrypted === "h2");

        const allowed = await engine.validateRotation("candidate", "user-1", compareFn);

        expect(allowed).toBe(false);
        expect(compareFn).toHaveBeenCalledTimes(2);
    });

    it("respects historyLimit when evaluating reuse", async () => {
        const engine = new IdentityPolicyEngine({
            historyLimit: 2,
            persistence: createPersistenceMock(["h1", "h2", "h3"]),
        });

        const compareFn = vi.fn(async (_plain: string | Uint8Array, encrypted: string) => encrypted === "h3");

        const allowed = await engine.validateRotation("candidate", "user-1", compareFn);

        expect(allowed).toBe(true);
        expect(compareFn).toHaveBeenCalledTimes(2);
    });

    it("supports custom history comparison strategies for advanced stores", async () => {
        const engine = new IdentityPolicyEngine({
            historyLimit: 2,
            normalizeTrim: true,
            persistence: createPersistenceMock(["h1", "h2", "h3"]),
        });

        const strategy = {
            isReused: vi.fn(async (context) => {
                expect(context).toMatchObject({
                    userId: "user-1",
                    plainPassword: "  candidate  ",
                    normalizedPassword: "candidate",
                    history: ["h1", "h2"],
                    historyLimit: 2,
                });

                return true;
            }),
        };

        const allowed = await engine.validateRotation("  candidate  ", "user-1", strategy);

        expect(allowed).toBe(false);
        expect(strategy.isReused).toHaveBeenCalledTimes(1);
    });

    it("provides a bulk-history helper for optimized remote adapters", async () => {
        const engine = new IdentityPolicyEngine({
            historyLimit: 2,
            normalizeTrim: true,
            persistence: createPersistenceMock(["h1", "h2", "h3"]),
        });

        const compareFn = vi.fn(async (normalizedPassword, history, context) => {
            expect(normalizedPassword).toBe("candidate");
            expect(history).toEqual(["h1", "h2"]);
            expect(context).toEqual({
                userId: "user-1",
                plainPassword: "  candidate  ",
                historyLimit: 2,
            });

            return true;
        });

        const comparator = createBulkPasswordHistoryComparisonStrategy(compareFn);
        const allowed = await engine.validateRotation("  candidate  ", "user-1", comparator);

        expect(allowed).toBe(false);
        expect(compareFn).toHaveBeenCalledTimes(1);
    });

    it("blocks password rotation when candidate includes previous secret substrings", async () => {
        const engine = new IdentityPolicyEngine({
            blockSubstringsFromPreviousSecrets: true,
            minPreviousSecretSubstringLength: 4,
            persistence: createPersistenceMock(["h1"], ["legacy", "abc"]),
        });

        const compareFn = vi.fn(async () => false);
        const allowed = await engine.validateRotation("MyLegacyPassword#2026", "user-1", compareFn);

        expect(allowed).toBe(false);
        expect(compareFn).not.toHaveBeenCalled();
    });

    it("ignores previous secret fragments shorter than the configured minimum", async () => {
        const engine = new IdentityPolicyEngine({
            blockSubstringsFromPreviousSecrets: true,
            minPreviousSecretSubstringLength: 5,
            persistence: createPersistenceMock(["h1"], ["legacy", "abcd"]),
        });

        const compareFn = vi.fn(async () => false);
        const allowed = await engine.validateRotation("abcd-safe-password", "user-1", compareFn);

        expect(allowed).toBe(true);
        expect(compareFn).toHaveBeenCalledTimes(1);
    });
});

describe("IdentityPolicyEngine - minimum password age", () => {
    it("allows password change when minimumPasswordAgeDays is disabled", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            persistence: createPersistenceMock(),
        });

        const allowed = engine.isMinimumPasswordAgeSatisfied("2026-06-04T00:00:00.000Z");

        expect(allowed).toBe(true);
        vi.useRealTimers();
    });

    it("blocks password change when minimum age has not been reached", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            minimumPasswordAgeDays: 7,
            persistence: createPersistenceMock(),
        });

        const allowed = engine.isMinimumPasswordAgeSatisfied("2026-06-01T00:00:00.000Z");

        expect(allowed).toBe(false);
        vi.useRealTimers();
    });

    it("allows password change when minimum age has been reached", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            minimumPasswordAgeDays: 7,
            persistence: createPersistenceMock(),
        });

        const allowed = engine.isMinimumPasswordAgeSatisfied("2026-05-29T00:00:00.000Z");

        expect(allowed).toBe(true);
        vi.useRealTimers();
    });
});

describe("IdentityPolicyEngine - expiry", () => {
    it("marks password as expired when age is greater or equal than expiryDays", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            persistence: createPersistenceMock(),
        });

        const expired = engine.isPasswordExpired("2026-03-07T00:00:00.000Z");

        expect(expired).toBe(true);
        vi.useRealTimers();
    });

    it("marks password as valid when still within expiry window", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            persistence: createPersistenceMock(),
        });

        const expired = engine.isPasswordExpired("2026-03-08T00:00:00.000Z");

        expect(expired).toBe(false);
        vi.useRealTimers();
    });

    it("returns remaining days until expiry", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            persistence: createPersistenceMock(),
        });

        const remainingDays = engine.daysUntilExpiry("2026-03-08T00:00:00.000Z");

        expect(remainingDays).toBe(1);
        vi.useRealTimers();
    });

    it("returns zero days when password is already expired", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            persistence: createPersistenceMock(),
        });

        const remainingDays = engine.daysUntilExpiry("2026-03-07T00:00:00.000Z");

        expect(remainingDays).toBe(0);
        vi.useRealTimers();
    });

    it("detects when an expired password is still inside grace period", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            gracePeriodDays: 7,
            persistence: createPersistenceMock(),
        });

        const inGrace = engine.isWithinGracePeriod("2026-03-06T00:00:00.000Z");

        expect(inGrace).toBe(true);
        vi.useRealTimers();
    });

    it("returns remaining days in grace period", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            gracePeriodDays: 7,
            persistence: createPersistenceMock(),
        });

        const remainingGraceDays = engine.daysRemainingInGracePeriod("2026-03-06T00:00:00.000Z");

        expect(remainingGraceDays).toBe(6);
        vi.useRealTimers();
    });

    it("returns false/zero outside grace period", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-06-05T00:00:00.000Z"));

        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            gracePeriodDays: 7,
            persistence: createPersistenceMock(),
        });

        const inGrace = engine.isWithinGracePeriod("2026-02-26T00:00:00.000Z");
        const remainingGraceDays = engine.daysRemainingInGracePeriod("2026-02-26T00:00:00.000Z");

        expect(inGrace).toBe(false);
        expect(remainingGraceDays).toBe(0);
        vi.useRealTimers();
    });
});

describe("normalizePasswordCreatedAt", () => {
    it("throws for invalid date string", () => {
        expect(() => normalizePasswordCreatedAt("not-a-date")).toThrow(
            "Invalid passwordCreatedAt ISO string.",
        );
    });

    it("accepts Date and ISO string", () => {
        const d1 = normalizePasswordCreatedAt(new Date("2026-01-01T00:00:00.000Z"));
        const d2 = normalizePasswordCreatedAt("2026-01-01T00:00:00.000Z");

        expect(d1.toISOString()).toBe("2026-01-01T00:00:00.000Z");
        expect(d2.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    });
});

describe("IdentityPolicyEngine - config validation", () => {
    it("throws when maxLength is lower than minLength", () => {
        expect(() => {
            new IdentityPolicyEngine({
                minLength: 10,
                maxLength: 8,
                persistence: createPersistenceMock(),
            });
        }).toThrow("maxLength must be greater than or equal to minLength.");
    });

    it("throws when minimumPasswordAgeDays is negative", () => {
        expect(() => {
            new IdentityPolicyEngine({
                minimumPasswordAgeDays: -1,
                persistence: createPersistenceMock(),
            });
        }).toThrow("minimumPasswordAgeDays must be a non-negative integer.");
    });

    it("throws when previous-secret substring blocking is enabled without the required callback", () => {
        expect(() => {
            new IdentityPolicyEngine({
                blockSubstringsFromPreviousSecrets: true,
                persistence: {
                    getPasswordHistory: async () => [],
                    saveNewPassword: async () => undefined,
                },
            });
        }).toThrow(
            "getPreviousPasswordSubstrings persistence callback is required when blockSubstringsFromPreviousSecrets is enabled.",
        );
    });

    it("throws when gracePeriodDays is negative", () => {
        expect(() => {
            new IdentityPolicyEngine({
                gracePeriodDays: -1,
                persistence: createPersistenceMock(),
            });
        }).toThrow("gracePeriodDays must be a non-negative integer.");
    });
});

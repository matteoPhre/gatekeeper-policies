import { describe, expect, it, vi } from "vitest";

import {
    createCodeSendExpiryHook,
    createStatusJsonExpiryMiddleware,
    evaluatePasswordExpiry,
} from "../src/http-adapters";

describe("evaluatePasswordExpiry", () => {
    it("returns not expired result and does not execute onExpired", async () => {
        const onExpired = vi.fn(async () => "blocked");

        const result = await evaluatePasswordExpiry(
            { headers: {} },
            {
                getUserIdAndDateFn: async () => ({
                    userId: "u1",
                    passwordCreatedAt: new Date("2026-06-01T00:00:00.000Z"),
                }),
                isPasswordExpired: () => false,
                onExpired,
            },
        );

        expect(result.expired).toBe(false);
        expect(result.subject.userId).toBe("u1");
        expect(onExpired).not.toHaveBeenCalled();
    });

    it("returns expired result and propagates onExpired return", async () => {
        const result = await evaluatePasswordExpiry(
            { headers: {} },
            {
                getUserIdAndDateFn: async () => ({
                    userId: "u1",
                    passwordCreatedAt: new Date("2024-01-01T00:00:00.000Z"),
                }),
                isPasswordExpired: () => true,
                onExpired: async ({ payload }) => payload.code,
            },
        );

        expect(result.expired).toBe(true);
        expect(result.expiredResult).toBe("PASSWORD_EXPIRED");
    });
});

describe("createStatusJsonExpiryMiddleware", () => {
    it("calls next when password is not expired", async () => {
        const middleware = createStatusJsonExpiryMiddleware({
            getUserIdAndDateFn: async () => ({
                userId: "u1",
                passwordCreatedAt: new Date(),
            }),
            isPasswordExpired: () => false,
        });

        const response = {
            status: vi.fn(() => ({ json: vi.fn() })),
        };
        const next = vi.fn();

        await middleware({} as unknown, response, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect(response.status).not.toHaveBeenCalled();
    });

    it("returns 403 json payload when password is expired", async () => {
        const json = vi.fn();
        const response = {
            status: vi.fn(() => ({ json })),
        };

        const middleware = createStatusJsonExpiryMiddleware({
            getUserIdAndDateFn: async () => ({
                userId: "u1",
                passwordCreatedAt: new Date("2020-01-01T00:00:00.000Z"),
            }),
            isPasswordExpired: () => true,
        });

        await middleware({} as unknown, response, vi.fn());

        expect(response.status).toHaveBeenCalledWith(403);
        expect(json).toHaveBeenCalledWith({ code: "PASSWORD_EXPIRED" });
    });

    it("forwards exceptions to next(error)", async () => {
        const expectedError = new Error("boom");
        const middleware = createStatusJsonExpiryMiddleware({
            getUserIdAndDateFn: async () => {
                throw expectedError;
            },
            isPasswordExpired: () => false,
        });

        const next = vi.fn();

        await middleware(
            {} as unknown,
            { status: vi.fn(() => ({ json: vi.fn() })) },
            next,
        );

        expect(next).toHaveBeenCalledWith(expectedError);
    });
});

describe("createCodeSendExpiryHook", () => {
    it("does nothing when password is not expired", async () => {
        const reply = {
            code: vi.fn(() => ({ send: vi.fn() })),
        };

        const hook = createCodeSendExpiryHook({
            getUserIdAndDateFn: async () => ({
                userId: "u1",
                passwordCreatedAt: new Date(),
            }),
            isPasswordExpired: () => false,
        });

        await hook({} as unknown, reply);

        expect(reply.code).not.toHaveBeenCalled();
    });

    it("returns 403 payload when password is expired", async () => {
        const send = vi.fn();
        const reply = {
            code: vi.fn(() => ({ send })),
        };

        const hook = createCodeSendExpiryHook({
            getUserIdAndDateFn: async () => ({
                userId: "u1",
                passwordCreatedAt: new Date("2020-01-01T00:00:00.000Z"),
            }),
            isPasswordExpired: () => true,
        });

        await hook({} as unknown, reply);

        expect(reply.code).toHaveBeenCalledWith(403);
        expect(send).toHaveBeenCalledWith({ code: "PASSWORD_EXPIRED" });
    });
});

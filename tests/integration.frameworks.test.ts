import express from "express";
import fastify from "fastify";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";

import {
    createCodeSendExpiryHook,
    createStatusJsonExpiryMiddleware,
    IdentityPolicyEngine,
} from "../src";

function toDateFromHeader(value: unknown): Date {
    const raw = Array.isArray(value) ? value[0] : value;
    return new Date(String(raw));
}

describe("integration - express", () => {
    it("blocks expired password with 403 payload", async () => {
        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            persistence: {
                getPasswordHistory: async () => [],
                saveNewPassword: async () => undefined,
            },
        });

        const app = express();

        app.use(
            createStatusJsonExpiryMiddleware({
                getUserIdAndDateFn: async (req: { headers: Record<string, unknown> }) => ({
                    userId: String(req.headers["x-user-id"] ?? "unknown"),
                    passwordCreatedAt: toDateFromHeader(req.headers["x-password-created-at"]),
                }),
                isPasswordExpired: (createdAt) => engine.isPasswordExpired(createdAt),
            }),
        );

        app.get("/protected", (_req, res) => {
            res.status(200).json({ ok: true });
        });

        const response = await request(app)
            .get("/protected")
            .set("x-user-id", "user-1")
            .set("x-password-created-at", "2025-01-01T00:00:00.000Z");

        expect(response.status).toBe(403);
        expect(response.body).toEqual({ code: "PASSWORD_EXPIRED" });
    });

    it("allows request when password is fresh", async () => {
        const engine = new IdentityPolicyEngine({
            expiryDays: 3650,
            persistence: {
                getPasswordHistory: async () => [],
                saveNewPassword: async () => undefined,
            },
        });

        const app = express();

        app.use(
            createStatusJsonExpiryMiddleware({
                getUserIdAndDateFn: async (req: { headers: Record<string, unknown> }) => ({
                    userId: String(req.headers["x-user-id"] ?? "unknown"),
                    passwordCreatedAt: toDateFromHeader(req.headers["x-password-created-at"]),
                }),
                isPasswordExpired: (createdAt) => engine.isPasswordExpired(createdAt),
            }),
        );

        app.get("/protected", (_req, res) => {
            res.status(200).json({ ok: true });
        });

        const response = await request(app)
            .get("/protected")
            .set("x-user-id", "user-1")
            .set("x-password-created-at", "2026-05-01T00:00:00.000Z");

        expect(response.status).toBe(200);
        expect(response.body).toEqual({ ok: true });
    });
});

describe("integration - fastify", () => {
    const instances: Array<ReturnType<typeof fastify>> = [];

    afterEach(async () => {
        while (instances.length > 0) {
            const instance = instances.pop();
            if (instance) {
                await instance.close();
            }
        }
    });

    it("blocks expired password with 403 payload", async () => {
        const engine = new IdentityPolicyEngine({
            expiryDays: 90,
            persistence: {
                getPasswordHistory: async () => [],
                saveNewPassword: async () => undefined,
            },
        });

        const app = fastify();
        instances.push(app);

        app.addHook(
            "preHandler",
            createCodeSendExpiryHook({
                getUserIdAndDateFn: async (req: { headers: Record<string, unknown> }) => ({
                    userId: String(req.headers["x-user-id"] ?? "unknown"),
                    passwordCreatedAt: toDateFromHeader(req.headers["x-password-created-at"]),
                }),
                isPasswordExpired: (createdAt) => engine.isPasswordExpired(createdAt),
            }),
        );

        app.get("/protected", async () => ({ ok: true }));

        const response = await app.inject({
            method: "GET",
            url: "/protected",
            headers: {
                "x-user-id": "user-1",
                "x-password-created-at": "2025-01-01T00:00:00.000Z",
            },
        });

        expect(response.statusCode).toBe(403);
        expect(response.json()).toEqual({ code: "PASSWORD_EXPIRED" });
    });

    it("allows request when password is fresh", async () => {
        const engine = new IdentityPolicyEngine({
            expiryDays: 3650,
            persistence: {
                getPasswordHistory: async () => [],
                saveNewPassword: async () => undefined,
            },
        });

        const app = fastify();
        instances.push(app);

        app.addHook(
            "preHandler",
            createCodeSendExpiryHook({
                getUserIdAndDateFn: async (req: { headers: Record<string, unknown> }) => ({
                    userId: String(req.headers["x-user-id"] ?? "unknown"),
                    passwordCreatedAt: toDateFromHeader(req.headers["x-password-created-at"]),
                }),
                isPasswordExpired: (createdAt) => engine.isPasswordExpired(createdAt),
            }),
        );

        app.get("/protected", async () => ({ ok: true }));

        const response = await app.inject({
            method: "GET",
            url: "/protected",
            headers: {
                "x-user-id": "user-1",
                "x-password-created-at": "2026-05-01T00:00:00.000Z",
            },
        });

        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({ ok: true });
    });
});

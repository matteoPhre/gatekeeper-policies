import { describe, expect, it } from "vitest";
import { createStatusJsonExpiryMiddleware, IdentityPolicyEngine } from "../src";

type CustomRequest = {
  auth: {
    userId: string;
    passwordCreatedAt: string;
  };
};

type CustomResponse = {
  statusCode?: number;
  payload?: unknown;
  status: (code: number) => {
    json: (body: unknown) => unknown;
  };
};

function createResponse(): CustomResponse {
  return {
    status(code: number) {
      this.statusCode = code;
      return {
        json: (body: unknown) => {
          this.payload = body;
          return body;
        },
      };
    },
  };
}

async function runCustomPipeline(
  middleware: (
    request: CustomRequest,
    response: CustomResponse,
    next: (err?: unknown) => void,
  ) => Promise<void>,
  request: CustomRequest,
): Promise<{
  proceeded: boolean;
  response: CustomResponse;
  nextError?: unknown;
}> {
  const response = createResponse();
  let proceeded = false;
  let nextError: unknown;

  await middleware(request, response, (err?: unknown) => {
    if (err) {
      nextError = err;
      return;
    }

    proceeded = true;
  });

  return { proceeded, response, nextError };
}

describe("integration example - custom runtime", () => {
  it("blocks expired credentials", async () => {
    const engine = new IdentityPolicyEngine({
      expiryDays: 90,
      persistence: {
        getPasswordHistory: async () => [],
        saveNewPassword: async () => undefined,
      },
    });

    const middleware = createStatusJsonExpiryMiddleware<
      CustomRequest,
      CustomResponse
    >({
      getUserIdAndDateFn: async (req) => ({
        userId: req.auth.userId,
        passwordCreatedAt: new Date(req.auth.passwordCreatedAt),
      }),
      isPasswordExpired: (createdAt) => engine.isPasswordExpired(createdAt),
    });

    const result = await runCustomPipeline(middleware, {
      auth: {
        userId: "user-42",
        passwordCreatedAt: "2025-01-01T00:00:00.000Z",
      },
    });

    expect(result.proceeded).toBe(false);
    expect(result.response.statusCode).toBe(403);
    expect(result.response.payload).toEqual({ code: "PASSWORD_EXPIRED" });
    expect(result.nextError).toBeUndefined();
  });

  it("continues pipeline for non-expired credentials", async () => {
    const engine = new IdentityPolicyEngine({
      expiryDays: 3650,
      persistence: {
        getPasswordHistory: async () => [],
        saveNewPassword: async () => undefined,
      },
    });

    const middleware = createStatusJsonExpiryMiddleware<
      CustomRequest,
      CustomResponse
    >({
      getUserIdAndDateFn: async (req) => ({
        userId: req.auth.userId,
        passwordCreatedAt: new Date(req.auth.passwordCreatedAt),
      }),
      isPasswordExpired: (createdAt) => engine.isPasswordExpired(createdAt),
    });

    const result = await runCustomPipeline(middleware, {
      auth: {
        userId: "user-42",
        passwordCreatedAt: "2026-05-01T00:00:00.000Z",
      },
    });

    expect(result.proceeded).toBe(true);
    expect(result.response.statusCode).toBeUndefined();
    expect(result.response.payload).toBeUndefined();
    expect(result.nextError).toBeUndefined();
  });
});

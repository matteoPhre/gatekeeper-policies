import { describe, expect, it, vi } from "vitest";
import { emitAuditEvent } from "../src/internal/audit.js";

describe("audit event hardening", () => {
  it("injects schemaVersion and redacts sensitive detail keys", async () => {
    const callback = vi.fn(async () => undefined);

    emitAuditEvent(callback, {
      type: "complexity",
      outcome: "fail",
      details: {
        password: "PlainText#2026",
        nested: {
          secretValue: "abc",
          note: "keep",
        },
      },
    });

    await Promise.resolve();

    expect(callback).toHaveBeenCalledTimes(1);
    const event = callback.mock.calls[0][0] as {
      schemaVersion: string;
      details: Record<string, unknown>;
    };

    expect(event.schemaVersion).toBe("1.0.0");
    expect(event.details.password).toBe("[REDACTED]");
    expect(event.details.nested).toEqual({
      secretValue: "[REDACTED]",
      note: "keep",
    });
  });
});

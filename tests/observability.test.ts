import { describe, expect, it, vi } from "vitest";
import { emitPolicyObservation } from "../src/internal/observability";

describe("emitPolicyObservation", () => {
  it("emits audit and metric events through a shared helper", () => {
    const auditEventCallback = vi.fn();
    const metricsHook = vi.fn();

    emitPolicyObservation(
      {
        auditEventCallback,
        metricsHook,
      },
      {
        type: "complexity",
        outcome: "pass",
        details: { mode: "shared-helper" },
      },
      {
        name: "password.complexity.evaluations",
        type: "counter",
        value: 1,
        attributes: { outcome: "pass" },
      },
    );

    expect(auditEventCallback).toHaveBeenCalledTimes(1);
    expect(metricsHook).toHaveBeenCalledTimes(1);
  });
});

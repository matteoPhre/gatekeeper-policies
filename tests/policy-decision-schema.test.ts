import { describe, expect, it } from "vitest";
import {
  POLICY_DECISION_SCHEMA_ID,
  policyDecisionJsonSchema,
  policyEvaluationResultJsonSchema,
} from "../src/policy-decision-schema.js";

describe("PolicyDecision JSON schema exports", () => {
  it("exports a stable schema id", () => {
    expect(POLICY_DECISION_SCHEMA_ID).toContain("policy-decision-1.0.0");
    expect(policyDecisionJsonSchema.$id).toBe(POLICY_DECISION_SCHEMA_ID);
  });

  it("models success/failure decision shape", () => {
    expect(policyDecisionJsonSchema.oneOf).toHaveLength(2);

    const failureShape = policyDecisionJsonSchema.oneOf[1] as {
      required: string[];
      properties: Record<string, unknown>;
    };

    expect(failureShape.required).toEqual(["success", "reason"]);
    expect(failureShape.properties.reason).toEqual({
      type: "string",
      minLength: 1,
    });
  });

  it("extends decision schema with optional trace", () => {
    expect(policyEvaluationResultJsonSchema.allOf).toHaveLength(2);
  });
});

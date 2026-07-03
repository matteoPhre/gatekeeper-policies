export const POLICY_DECISION_SCHEMA_ID =
  "https://schemas.matteophre.dev/gatekeeper-policies/policy-decision-1.0.0.json";

export const policyDecisionJsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: POLICY_DECISION_SCHEMA_ID,
  title: "PolicyDecision",
  description:
    "Typed policy decision contract for pass/fail outcomes with optional machine-readable metadata.",
  oneOf: [
    {
      type: "object",
      additionalProperties: false,
      required: ["success"],
      properties: {
        success: { const: true },
      },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["success", "reason"],
      properties: {
        success: { const: false },
        reason: {
          type: "string",
          minLength: 1,
        },
        meta: {
          type: "object",
          additionalProperties: true,
        },
      },
    },
  ],
} as const;

export const policyEvaluationResultJsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://schemas.matteophre.dev/gatekeeper-policies/policy-evaluation-result-1.0.0.json",
  title: "PolicyEvaluationResult",
  allOf: [
    {
      $ref: POLICY_DECISION_SCHEMA_ID,
    },
    {
      type: "object",
      properties: {
        trace: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["step", "success"],
            properties: {
              step: { type: "string", minLength: 1 },
              success: { type: "boolean" },
              meta: { type: "object", additionalProperties: true },
            },
          },
        },
      },
      additionalProperties: true,
    },
  ],
} as const;

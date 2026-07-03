import type {
  PasswordAuditEvent,
  PasswordAuditEventCallback,
} from "../types/interfaces.js";

const POLICY_VERSION = "1.2.1";
const AUDIT_SCHEMA_VERSION = "1.0.0";
const REDACTED_VALUE = "[REDACTED]";
const MAX_REDACTION_DEPTH = 8;
const SENSITIVE_KEY_PATTERN =
  /(password|passphrase|secret|token|credential|plaintext|plain)/i;

export function emitAuditEvent(
  callback: PasswordAuditEventCallback | undefined,
  event: Omit<PasswordAuditEvent, "schemaVersion" | "policyVersion" | "timestamp">,
): void {
  if (!callback) {
    return;
  }

  try {
    void Promise.resolve(callback(cloneAuditEvent(createAuditEvent(event)))).catch(
      () => undefined,
    );
  } catch {
    return;
  }
}

function cloneAuditEvent(event: PasswordAuditEvent): PasswordAuditEvent {
  const sanitizedDetails = sanitizeForAudit(event.details);

  return {
    ...event,
    schemaVersion: event.schemaVersion,
    policyVersion: event.policyVersion,
    timestamp: event.timestamp,
    details: sanitizedDetails ? { ...sanitizedDetails } : undefined,
  };
}

export function createAuditEvent(
  event: Omit<PasswordAuditEvent, "schemaVersion" | "policyVersion" | "timestamp">,
): PasswordAuditEvent {
  return {
    ...event,
    schemaVersion: AUDIT_SCHEMA_VERSION,
    policyVersion: POLICY_VERSION,
    timestamp: new Date().toISOString(),
  };
}

function sanitizeForAudit(
  details: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!details) {
    return undefined;
  }

  return sanitizeUnknown(details, 0) as Record<string, unknown>;
}

function sanitizeUnknown(value: unknown, depth: number): unknown {
  if (depth > MAX_REDACTION_DEPTH) {
    return REDACTED_VALUE;
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    value === null ||
    value === undefined
  ) {
    return value;
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: REDACTED_VALUE,
    };
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeUnknown(entry, depth + 1));
  }

  if (typeof value === "object") {
    const output: Record<string, unknown> = {};

    for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        output[key] = REDACTED_VALUE;
        continue;
      }

      output[key] = sanitizeUnknown(nestedValue, depth + 1);
    }

    return output;
  }

  return REDACTED_VALUE;
}

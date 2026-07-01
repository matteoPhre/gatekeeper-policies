import type {
  PasswordAuditEvent,
  PasswordAuditEventCallback,
} from "../types/interfaces.js";

const POLICY_VERSION = "1.2.1";

export function emitAuditEvent(
  callback: PasswordAuditEventCallback | undefined,
  event: Omit<PasswordAuditEvent, "policyVersion" | "timestamp">,
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
  return {
    ...event,
    policyVersion: event.policyVersion,
    timestamp: event.timestamp,
    details: event.details ? { ...event.details } : undefined,
  };
}

export function createAuditEvent(
  event: Omit<PasswordAuditEvent, "policyVersion" | "timestamp">,
): PasswordAuditEvent {
  return {
    ...event,
    policyVersion: POLICY_VERSION,
    timestamp: new Date().toISOString(),
  };
}

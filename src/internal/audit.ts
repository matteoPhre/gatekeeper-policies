import type {
  PasswordAuditEvent,
  PasswordAuditEventCallback,
} from "../types/interfaces.js";

export function emitAuditEvent(
  callback: PasswordAuditEventCallback | undefined,
  event: PasswordAuditEvent,
): void {
  if (!callback) {
    return;
  }

  try {
    void Promise.resolve(callback(cloneAuditEvent(event))).catch(
      () => undefined,
    );
  } catch {
    return;
  }
}

function cloneAuditEvent(event: PasswordAuditEvent): PasswordAuditEvent {
  return {
    ...event,
    details: event.details ? { ...event.details } : undefined,
  };
}

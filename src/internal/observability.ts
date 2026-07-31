import type {
  PasswordAuditEvent,
  PasswordAuditEventCallback,
  PasswordMetricEvent,
  PasswordMetricsHook,
} from "../types/interfaces.js";
import { emitAuditEvent } from "./audit.js";
import { emitMetricEvent } from "./metrics.js";

export interface PolicyObservationHooks {
  auditEventCallback?: PasswordAuditEventCallback;
  metricsHook?: PasswordMetricsHook;
}

export function emitPolicyObservation(
  hooks: PolicyObservationHooks,
  auditEvent: Omit<PasswordAuditEvent, "schemaVersion" | "policyVersion" | "timestamp">,
  metricEvent: Omit<PasswordMetricEvent, "timestamp">,
): void {
  emitAuditEvent(hooks.auditEventCallback, auditEvent);
  emitMetricEvent(hooks.metricsHook, metricEvent);
}

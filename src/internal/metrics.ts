import type {
  PasswordMetricEvent,
  PasswordMetricsHook,
} from "../types/interfaces.js";

export function emitMetricEvent(
  hook: PasswordMetricsHook | undefined,
  event: Omit<PasswordMetricEvent, "timestamp">,
): void {
  if (!hook) {
    return;
  }

  const payload: PasswordMetricEvent = {
    ...event,
    timestamp: new Date().toISOString(),
  };

  try {
    void Promise.resolve(hook(cloneMetricEvent(payload))).catch(() => undefined);
  } catch {
    return;
  }
}

function cloneMetricEvent(event: PasswordMetricEvent): PasswordMetricEvent {
  return {
    ...event,
    attributes: event.attributes ? { ...event.attributes } : undefined,
    timestamp: event.timestamp,
  };
}

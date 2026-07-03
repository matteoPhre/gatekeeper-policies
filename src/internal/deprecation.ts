const emittedWarnings = new Set<string>();

export function emitDeprecationWarning(
  enabled: boolean,
  methodName: string,
  replacement: string,
  removalTarget: string,
): void {
  if (!enabled) {
    return;
  }

  const key = `${methodName}->${replacement}@${removalTarget}`;
  if (emittedWarnings.has(key)) {
    return;
  }

  emittedWarnings.add(key);
  process.emitWarning(
    `${methodName} is deprecated and will be removed in ${removalTarget}. Use ${replacement} instead.`,
    {
      code: "GATEKEEPER_DEPRECATED_API",
      type: "DeprecationWarning",
    },
  );
}

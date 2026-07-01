import {
  type BulkPasswordHistoryCompareFn,
  type IdentityPolicyEngineOptions,
  type PasswordCompareFn,
  type PasswordCompromisedPasswordValidator,
  type PasswordCreatedAtInput,
  type PasswordEntropyValidator,
  type PasswordHistoryComparator,
  type PasswordHistoryComparisonStrategy,
  type PasswordPolicyConfig,
  type PasswordUnicodeNormalizationForm,
  ResolvedIdentityPolicyEngineOptions,
} from "../types/interfaces.js";

export const MS_PER_DAY = 24 * 60 * 60 * 1000;

export const DEFAULT_POLICY_CONFIG: Required<PasswordPolicyConfig> = {
  minLength: 12,
  maxLength: 128,
  normalizeTrim: false,
  normalizeUnicode: false,
  unicodeNormalizationForm: "NFKC",
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
  denyList: [],
  preventRepeatedChars: false,
  maxRepeatedChars: 3,
  preventSequentialChars: false,
  maxSequentialChars: 3,
  expiryDays: 90,
  expiryWarningDays: 0,
  gracePeriodDays: 0,
  minimumPasswordAgeDays: 0,
  historyLimit: 5,
  blockSubstringsFromPreviousSecrets: false,
  minPreviousSecretSubstringLength: 4,
};

export function normalizePasswordCreatedAt(
  passwordCreatedAt: PasswordCreatedAtInput,
): Date {
  if (passwordCreatedAt instanceof Date) {
    if (Number.isNaN(passwordCreatedAt.getTime())) {
      throw new TypeError("Invalid passwordCreatedAt date.");
    }

    return passwordCreatedAt;
  }

  const parsed = new Date(passwordCreatedAt);
  if (Number.isNaN(parsed.getTime())) {
    throw new TypeError("Invalid passwordCreatedAt ISO string.");
  }

  return parsed;
}

export function createBulkPasswordHistoryComparisonStrategy(
  compareFn: BulkPasswordHistoryCompareFn,
): PasswordHistoryComparisonStrategy {
  return {
    async isReused(context) {
      return compareFn(context.normalizedPassword, context.history, {
        userId: context.userId,
        plainPassword: context.plainPassword,
        historyLimit: context.historyLimit,
      });
    },
  };
}

export function createScoreBasedEntropyValidator(
  scoreFn: (password: string) => number | Promise<number>,
  minimumScore: number,
): PasswordEntropyValidator {
  if (!Number.isFinite(minimumScore)) {
    throw new RangeError("minimumScore must be a finite number.");
  }

  return async ({ normalizedPassword }) => {
    const score = await scoreFn(normalizedPassword);

    return {
      isValid: score >= minimumScore,
      score,
      details: {
        minimumScore,
      },
    };
  };
}

export function createCompromisedPasswordDictionaryValidator(
  dictionary: readonly string[],
): PasswordCompromisedPasswordValidator {
  const normalizedDictionary = new Set(
    dictionary
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry.length > 0),
  );

  return ({ normalizedPassword }) => {
    const isCompromised = normalizedDictionary.has(
      normalizedPassword.trim().toLowerCase(),
    );

    return {
      isCompromised,
      details: {
        dictionarySize: normalizedDictionary.size,
      },
    };
  };
}

export function toUtcStartOfDay(value: PasswordCreatedAtInput): Date {
  const normalized = normalizePasswordCreatedAt(value);

  return new Date(
    Date.UTC(
      normalized.getUTCFullYear(),
      normalized.getUTCMonth(),
      normalized.getUTCDate(),
    ),
  );
}

export function addUtcCalendarDays(
  value: PasswordCreatedAtInput,
  days: number,
): Date {
  if (!Number.isInteger(days)) {
    throw new RangeError("days must be an integer.");
  }

  const utcStart = toUtcStartOfDay(value);
  return new Date(
    Date.UTC(
      utcStart.getUTCFullYear(),
      utcStart.getUTCMonth(),
      utcStart.getUTCDate() + days,
    ),
  );
}

export function daysBetweenUtcCalendarDates(
  start: PasswordCreatedAtInput,
  end: PasswordCreatedAtInput,
): number {
  const utcStart = toUtcStartOfDay(start).getTime();
  const utcEnd = toUtcStartOfDay(end).getTime();

  return Math.round((utcEnd - utcStart) / MS_PER_DAY);
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) {
    return value;
  }

  for (const key of Object.keys(value as Record<string, unknown>)) {
    const nested = (value as Record<string, unknown>)[key];
    if (typeof nested === "object" && nested !== null) {
      deepFreeze(nested);
    }
  }

  return Object.freeze(value);
}

export function resolveEngineOptions(
  options: IdentityPolicyEngineOptions,
): ResolvedIdentityPolicyEngineOptions {
  if (!options || !options.persistence) {
    throw new TypeError("IdentityPolicyEngine requires persistence callbacks.");
  }

  const config: ResolvedIdentityPolicyEngineOptions = {
    minLength: options.minLength ?? DEFAULT_POLICY_CONFIG.minLength,
    maxLength: options.maxLength ?? DEFAULT_POLICY_CONFIG.maxLength,
    normalizeTrim: options.normalizeTrim ?? DEFAULT_POLICY_CONFIG.normalizeTrim,
    normalizeUnicode:
      options.normalizeUnicode ?? DEFAULT_POLICY_CONFIG.normalizeUnicode,
    unicodeNormalizationForm:
      options.unicodeNormalizationForm ??
      DEFAULT_POLICY_CONFIG.unicodeNormalizationForm,
    requireUppercase:
      options.requireUppercase ?? DEFAULT_POLICY_CONFIG.requireUppercase,
    requireLowercase:
      options.requireLowercase ?? DEFAULT_POLICY_CONFIG.requireLowercase,
    requireNumbers:
      options.requireNumbers ?? DEFAULT_POLICY_CONFIG.requireNumbers,
    requireSymbols:
      options.requireSymbols ?? DEFAULT_POLICY_CONFIG.requireSymbols,
    denyList: options.denyList ?? DEFAULT_POLICY_CONFIG.denyList,
    preventRepeatedChars:
      options.preventRepeatedChars ??
      DEFAULT_POLICY_CONFIG.preventRepeatedChars,
    maxRepeatedChars:
      options.maxRepeatedChars ?? DEFAULT_POLICY_CONFIG.maxRepeatedChars,
    preventSequentialChars:
      options.preventSequentialChars ??
      DEFAULT_POLICY_CONFIG.preventSequentialChars,
    maxSequentialChars:
      options.maxSequentialChars ?? DEFAULT_POLICY_CONFIG.maxSequentialChars,
    expiryDays: options.expiryDays ?? DEFAULT_POLICY_CONFIG.expiryDays,
    expiryWarningDays:
      options.expiryWarningDays ?? DEFAULT_POLICY_CONFIG.expiryWarningDays,
    gracePeriodDays:
      options.gracePeriodDays ?? DEFAULT_POLICY_CONFIG.gracePeriodDays,
    minimumPasswordAgeDays:
      options.minimumPasswordAgeDays ??
      DEFAULT_POLICY_CONFIG.minimumPasswordAgeDays,
    historyLimit: options.historyLimit ?? DEFAULT_POLICY_CONFIG.historyLimit,
    blockSubstringsFromPreviousSecrets:
      options.blockSubstringsFromPreviousSecrets ??
      DEFAULT_POLICY_CONFIG.blockSubstringsFromPreviousSecrets,
    minPreviousSecretSubstringLength:
      options.minPreviousSecretSubstringLength ??
      DEFAULT_POLICY_CONFIG.minPreviousSecretSubstringLength,
    persistence: options.persistence,
    auditEventCallback: options.auditEventCallback,
    entropyValidator: options.entropyValidator,
    compromisedPasswordValidator: options.compromisedPasswordValidator,
  };

  if (!Number.isInteger(config.minLength) || config.minLength < 1) {
    throw new RangeError("minLength must be an integer greater than 0.");
  }

  if (!Number.isInteger(config.maxLength) || config.maxLength < 1) {
    throw new RangeError("maxLength must be an integer greater than 0.");
  }

  if (config.maxLength < config.minLength) {
    throw new RangeError(
      "maxLength must be greater than or equal to minLength.",
    );
  }

  if (!Array.isArray(config.denyList)) {
    throw new TypeError("denyList must be an array of strings.");
  }

  if (config.denyList.some((entry) => typeof entry !== "string")) {
    throw new TypeError("denyList must contain only strings.");
  }

  if (
    !Number.isInteger(config.maxRepeatedChars) ||
    config.maxRepeatedChars < 2
  ) {
    throw new RangeError(
      "maxRepeatedChars must be an integer greater than or equal to 2.",
    );
  }

  if (
    !Number.isInteger(config.maxSequentialChars) ||
    config.maxSequentialChars < 2
  ) {
    throw new RangeError(
      "maxSequentialChars must be an integer greater than or equal to 2.",
    );
  }

  if (!isValidUnicodeNormalizationForm(config.unicodeNormalizationForm)) {
    throw new RangeError(
      "unicodeNormalizationForm must be one of NFC, NFD, NFKC, NFKD.",
    );
  }

  if (!Number.isInteger(config.expiryDays) || config.expiryDays < 1) {
    throw new RangeError("expiryDays must be an integer greater than 0.");
  }

  if (
    !Number.isInteger(config.expiryWarningDays) ||
    config.expiryWarningDays < 0
  ) {
    throw new RangeError("expiryWarningDays must be a non-negative integer.");
  }

  if (!Number.isInteger(config.gracePeriodDays) || config.gracePeriodDays < 0) {
    throw new RangeError("gracePeriodDays must be a non-negative integer.");
  }

  if (
    !Number.isInteger(config.minimumPasswordAgeDays) ||
    config.minimumPasswordAgeDays < 0
  ) {
    throw new RangeError(
      "minimumPasswordAgeDays must be a non-negative integer.",
    );
  }

  if (!Number.isInteger(config.historyLimit) || config.historyLimit < 1) {
    throw new RangeError("historyLimit must be an integer greater than 0.");
  }

  if (
    !Number.isInteger(config.minPreviousSecretSubstringLength) ||
    config.minPreviousSecretSubstringLength < 1
  ) {
    throw new RangeError(
      "minPreviousSecretSubstringLength must be an integer greater than 0.",
    );
  }

  if (
    config.blockSubstringsFromPreviousSecrets &&
    typeof config.persistence.getPreviousPasswordSubstrings !== "function"
  ) {
    throw new TypeError(
      "getPreviousPasswordSubstrings persistence callback is required when blockSubstringsFromPreviousSecrets is enabled.",
    );
  }

  return deepFreeze(config);
}

export function isInDenyList(
  password: string,
  denyList: string[],
  config: ResolvedIdentityPolicyEngineOptions,
): boolean {
  const normalizedPassword = password.toLowerCase();
  return denyList.some((entry) => {
    const normalizedEntry = normalizePasswordInput(entry, config)
      .trim()
      .toLowerCase();
    return (
      normalizedEntry.length > 0 && normalizedPassword.includes(normalizedEntry)
    );
  });
}

export function normalizePasswordInput(
  value: string,
  config: Pick<
    ResolvedIdentityPolicyEngineOptions,
    "normalizeTrim" | "normalizeUnicode" | "unicodeNormalizationForm"
  >,
): string {
  let normalizedValue = value;

  if (config.normalizeTrim) {
    normalizedValue = normalizedValue.trim();
  }

  if (config.normalizeUnicode) {
    normalizedValue = normalizedValue.normalize(
      config.unicodeNormalizationForm,
    );
  }

  return normalizedValue;
}

function isValidUnicodeNormalizationForm(
  value: string,
): value is PasswordUnicodeNormalizationForm {
  return (
    value === "NFC" || value === "NFD" || value === "NFKC" || value === "NFKD"
  );
}

export function isPasswordCompareFn(
  comparator: PasswordHistoryComparator,
): comparator is PasswordCompareFn {
  return typeof comparator === "function";
}

export function hasBlockedPreviousSecretSubstring(
  normalizedPassword: string,
  previousSubstrings: readonly string[] | undefined,
  config: Pick<
    ResolvedIdentityPolicyEngineOptions,
    | "normalizeTrim"
    | "normalizeUnicode"
    | "unicodeNormalizationForm"
    | "minPreviousSecretSubstringLength"
  >,
): boolean {
  if (!previousSubstrings || previousSubstrings.length === 0) {
    return false;
  }

  const candidate = normalizedPassword.toLowerCase();

  return previousSubstrings.some((entry) => {
    const normalizedEntry = normalizePasswordInput(entry, config)
      .trim()
      .toLowerCase();

    return (
      normalizedEntry.length >= config.minPreviousSecretSubstringLength &&
      candidate.includes(normalizedEntry)
    );
  });
}

export function hasRepeatedChars(password: string, threshold: number): boolean {
  let runLength = 1;

  for (let index = 1; index < password.length; index += 1) {
    if (password[index] === password[index - 1]) {
      runLength += 1;
      if (runLength > threshold) {
        return true;
      }
    } else {
      runLength = 1;
    }
  }

  return false;
}

export function hasSequentialChars(
  password: string,
  threshold: number,
): boolean {
  if (password.length < threshold) {
    return false;
  }

  let ascendingRun = 1;
  let descendingRun = 1;

  for (let index = 1; index < password.length; index += 1) {
    const previous = password.charCodeAt(index - 1);
    const current = password.charCodeAt(index);
    const diff = current - previous;

    if (diff === 1) {
      ascendingRun += 1;
    } else {
      ascendingRun = 1;
    }

    if (diff === -1) {
      descendingRun += 1;
    } else {
      descendingRun = 1;
    }

    if (ascendingRun >= threshold || descendingRun >= threshold) {
      return true;
    }
  }

  return false;
}

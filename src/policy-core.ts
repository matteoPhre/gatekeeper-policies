import type {
  LockoutDecisionCode,
  PolicyDecision,
  PolicyEvaluationResult,
  PasswordLockoutConfig,
  PasswordLockoutState,
  PasswordLockoutStateStore,
  PolicyTraceStep,
} from "./types/interfaces.js";

export type PasswordValidationCode =
  | "PASSWORD_TOO_SHORT"
  | "PASSWORD_TOO_LONG"
  | "PASSWORD_NO_UPPERCASE"
  | "PASSWORD_NO_LOWERCASE"
  | "PASSWORD_NO_NUMBER"
  | "PASSWORD_NO_SYMBOL"
  | "PASSWORD_REUSED"
  | "PASSWORD_SUBSTRING_MATCH"
  | "PASSWORD_EXPIRED";

export type { PolicyDecision, PolicyEvaluationResult, PolicyTraceStep } from "./types/interfaces.js";

export type FailureMode = "fail_open" | "fail_closed";

export interface RuleContext {
  password: string;
  normalizedPassword: string;
  config: Readonly<PasswordComplexityConfig>;
}

export type PasswordRule = (
  ctx: RuleContext,
) => Promise<PolicyDecision<PasswordValidationCode>>;

export interface PasswordComplexityConfig {
  minLength: number;
  maxLength: number;
  normalizeTrim: boolean;
  normalizeUnicode: boolean;
  unicodeNormalizationForm: "NFC" | "NFD" | "NFKC" | "NFKD";
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  denyList: readonly string[];
  preventRepeatedChars: boolean;
  maxRepeatedChars: number;
  preventSequentialChars: boolean;
  maxSequentialChars: number;
  extensionRules?: readonly PasswordRule[];
}

export interface PasswordRotationConfig {
  historyLimit: number;
  blockSubstringsFromPreviousSecrets: boolean;
  minPreviousSecretSubstringLength: number;
}

export interface PasswordExpiryConfig {
  expiryDays: number;
}

export interface RotationDependencies {
  getPasswordHistory(userId: string): Promise<string[]>;
  getPreviousPasswordSubstrings?(userId: string): Promise<string[]>;
}

export type RotationComparator = (
  normalizedPassword: string,
  previousHash: string,
) => Promise<boolean>;

export interface EvaluationOptions {
  trace?: boolean;
}

export interface EngineRuntimeOptions {
  failureMode?: FailureMode;
}

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function deepFreeze<T>(value: T): Readonly<T> {
  if (typeof value !== "object" || value === null) {
    return value;
  }

  const target = value as Record<string, unknown>;
  for (const key of Object.keys(target)) {
    const nested = target[key];
    if (typeof nested === "object" && nested !== null) {
      deepFreeze(nested);
    }
  }

  return Object.freeze(value);
}

function withTrace<TReason extends string>(
  decision: PolicyDecision<TReason>,
  trace: PolicyTraceStep[] | undefined,
): PolicyEvaluationResult<TReason> {
  return trace ? { ...decision, trace } : decision;
}

function createTraceCollector(enabled: boolean | undefined): {
  trace: PolicyTraceStep[] | undefined;
  add: (step: string, success: boolean, meta?: Readonly<Record<string, unknown>>) => void;
} {
  if (!enabled) {
    return {
      trace: undefined,
      add: () => undefined,
    };
  }

  const trace: PolicyTraceStep[] = [];
  return {
    trace,
    add: (step, success, meta) => {
      trace.push(meta ? { step, success, meta } : { step, success });
    },
  };
}

function normalizePassword(
  password: string,
  config: Readonly<Pick<PasswordComplexityConfig, "normalizeTrim" | "normalizeUnicode" | "unicodeNormalizationForm">>,
): string {
  let normalized = password;
  if (config.normalizeTrim) {
    normalized = normalized.trim();
  }
  if (config.normalizeUnicode) {
    normalized = normalized.normalize(config.unicodeNormalizationForm);
  }
  return normalized;
}

function hasRepeatedChars(password: string, threshold: number): boolean {
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

function hasSequentialChars(password: string, threshold: number): boolean {
  if (password.length < threshold) {
    return false;
  }

  let ascendingRun = 1;
  let descendingRun = 1;
  for (let index = 1; index < password.length; index += 1) {
    const previous = password.charCodeAt(index - 1);
    const current = password.charCodeAt(index);
    const diff = current - previous;

    ascendingRun = diff === 1 ? ascendingRun + 1 : 1;
    descendingRun = diff === -1 ? descendingRun + 1 : 1;

    if (ascendingRun >= threshold || descendingRun >= threshold) {
      return true;
    }
  }
  return false;
}

export class PasswordComplexityEngine {
  private readonly config: Readonly<PasswordComplexityConfig>;

  public constructor(config: PasswordComplexityConfig) {
    this.config = deepFreeze({
      ...config,
      denyList: [...config.denyList],
      extensionRules: config.extensionRules ? [...config.extensionRules] : undefined,
    });
  }

  public async evaluate(
    password: string,
    options?: EvaluationOptions,
  ): Promise<PolicyEvaluationResult<PasswordValidationCode>> {
    const { trace, add } = createTraceCollector(options?.trace);
    const normalizedPassword = normalizePassword(password, this.config);

    const fail = (
      step: string,
      reason: PasswordValidationCode,
      meta?: Readonly<Record<string, unknown>>,
    ): PolicyEvaluationResult<PasswordValidationCode> => {
      add(step, false, meta);
      return withTrace(
        meta ? { success: false, reason, meta } : { success: false, reason },
        trace,
      );
    };

    if (normalizedPassword.length < this.config.minLength) {
      return fail("minLength", "PASSWORD_TOO_SHORT", {
        minLength: this.config.minLength,
        actualLength: normalizedPassword.length,
      });
    }
    add("minLength", true);

    if (normalizedPassword.length > this.config.maxLength) {
      return fail("maxLength", "PASSWORD_TOO_LONG", {
        maxLength: this.config.maxLength,
        actualLength: normalizedPassword.length,
      });
    }
    add("maxLength", true);

    if (this.config.requireUppercase && !/[A-Z]/.test(normalizedPassword)) {
      return fail("uppercase", "PASSWORD_NO_UPPERCASE");
    }
    add("uppercase", true);

    if (this.config.requireLowercase && !/[a-z]/.test(normalizedPassword)) {
      return fail("lowercase", "PASSWORD_NO_LOWERCASE");
    }
    add("lowercase", true);

    if (this.config.requireNumbers && !/[0-9]/.test(normalizedPassword)) {
      return fail("number", "PASSWORD_NO_NUMBER");
    }
    add("number", true);

    if (
      this.config.requireSymbols &&
      !/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(normalizedPassword)
    ) {
      return fail("symbol", "PASSWORD_NO_SYMBOL");
    }
    add("symbol", true);

    const lowerPassword = normalizedPassword.toLowerCase();
    for (const denyEntry of this.config.denyList) {
      const normalizedEntry = normalizePassword(denyEntry, this.config)
        .trim()
        .toLowerCase();
      if (normalizedEntry.length > 0 && lowerPassword.includes(normalizedEntry)) {
        return fail("denyList", "PASSWORD_SUBSTRING_MATCH", {
          entry: normalizedEntry,
        });
      }
    }
    add("denyList", true);

    if (
      this.config.preventRepeatedChars &&
      hasRepeatedChars(normalizedPassword, this.config.maxRepeatedChars)
    ) {
      return fail("repeatedChars", "PASSWORD_SUBSTRING_MATCH", {
        maxRepeatedChars: this.config.maxRepeatedChars,
      });
    }
    add("repeatedChars", true);

    if (
      this.config.preventSequentialChars &&
      hasSequentialChars(normalizedPassword, this.config.maxSequentialChars)
    ) {
      return fail("sequentialChars", "PASSWORD_SUBSTRING_MATCH", {
        maxSequentialChars: this.config.maxSequentialChars,
      });
    }
    add("sequentialChars", true);

    if (this.config.extensionRules && this.config.extensionRules.length > 0) {
      for (let index = 0; index < this.config.extensionRules.length; index += 1) {
        const rule = this.config.extensionRules[index];
        const ruleStep = `extensionRule:${index}`;
        const ruleDecision = await rule({
          password,
          normalizedPassword,
          config: this.config,
        });

        if (!ruleDecision.success) {
          return fail(ruleStep, ruleDecision.reason, ruleDecision.meta);
        }

        add(ruleStep, true);
      }
    }

    return withTrace({ success: true }, trace);
  }
}

export class PasswordRotationEngine {
  private readonly config: Readonly<PasswordRotationConfig>;
  private readonly deps: Readonly<RotationDependencies>;
  private readonly failureMode: FailureMode;

  public constructor(
    config: PasswordRotationConfig,
    deps: RotationDependencies,
    options?: EngineRuntimeOptions,
  ) {
    this.config = deepFreeze({ ...config });
    this.deps = deepFreeze({ ...deps });
    this.failureMode = options?.failureMode ?? "fail_closed";
  }

  public async evaluate(
    plainPassword: string,
    userId: string,
    comparator: RotationComparator,
    options?: EvaluationOptions,
  ): Promise<PolicyEvaluationResult<PasswordValidationCode>> {
    const { trace, add } = createTraceCollector(options?.trace);
    const normalized = plainPassword;

    try {
      if (this.config.blockSubstringsFromPreviousSecrets) {
        const fragments = await this.deps.getPreviousPasswordSubstrings?.(userId);
        if (fragments && fragments.length > 0) {
          const candidate = normalized.toLowerCase();
          for (const entry of fragments) {
            const fragment = entry.trim().toLowerCase();
            if (
              fragment.length >= this.config.minPreviousSecretSubstringLength &&
              candidate.includes(fragment)
            ) {
              add("substringHistory", false, { fragment });
              return withTrace(
                { success: false, reason: "PASSWORD_SUBSTRING_MATCH" },
                trace,
              );
            }
          }
        }
      }
      add("substringHistory", true);

      const history = await this.deps.getPasswordHistory(userId);
      const limitedHistory = history.slice(0, this.config.historyLimit);
      for (const previousHash of limitedHistory) {
        const reused = await comparator(normalized, previousHash);
        if (reused) {
          add("historyCompare", false);
          return withTrace({ success: false, reason: "PASSWORD_REUSED" }, trace);
        }
      }
      add("historyCompare", true);

      return withTrace({ success: true }, trace);
    } catch (error) {
      add("rotationFailure", false, {
        error: error instanceof Error ? error.message : "unknown_error",
      });

      if (this.failureMode === "fail_open") {
        return withTrace({ success: true }, trace);
      }

      return withTrace(
        {
          success: false,
          reason: "PASSWORD_REUSED",
          meta: { failureMode: this.failureMode },
        },
        trace,
      );
    }
  }
}

export class PasswordExpiryEngine {
  private readonly config: Readonly<PasswordExpiryConfig>;
  private readonly failureMode: FailureMode;

  public constructor(config: PasswordExpiryConfig, options?: EngineRuntimeOptions) {
    this.config = deepFreeze({ ...config });
    this.failureMode = options?.failureMode ?? "fail_closed";
  }

  public async evaluate(
    passwordCreatedAt: Date | string,
    options?: EvaluationOptions,
  ): Promise<PolicyEvaluationResult<PasswordValidationCode>> {
    const { trace, add } = createTraceCollector(options?.trace);

    try {
      const createdAt =
        passwordCreatedAt instanceof Date
          ? passwordCreatedAt
          : new Date(passwordCreatedAt);

      if (Number.isNaN(createdAt.getTime())) {
        throw new TypeError("Invalid passwordCreatedAt value.");
      }

      const ageInMs = Date.now() - createdAt.getTime();
      const maxAgeInMs = this.config.expiryDays * MS_PER_DAY;
      const expired = ageInMs >= maxAgeInMs;

      if (expired) {
        add("expiryWindow", false, { expiryDays: this.config.expiryDays });
        return withTrace({ success: false, reason: "PASSWORD_EXPIRED" }, trace);
      }

      add("expiryWindow", true);
      return withTrace({ success: true }, trace);
    } catch (error) {
      add("expiryFailure", false, {
        error: error instanceof Error ? error.message : "unknown_error",
      });

      if (this.failureMode === "fail_open") {
        return withTrace({ success: true }, trace);
      }

      return withTrace(
        {
          success: false,
          reason: "PASSWORD_EXPIRED",
          meta: { failureMode: this.failureMode },
        },
        trace,
      );
    }
  }
}

export class PasswordLockoutEngine {
  private readonly config: Readonly<PasswordLockoutConfig>;
  private readonly store: Readonly<PasswordLockoutStateStore>;

  public constructor(
    config: PasswordLockoutConfig,
    store: PasswordLockoutStateStore,
  ) {
    this.config = deepFreeze({ ...config });
    this.store = deepFreeze({ ...store });
  }

  public async evaluateAttempt(
    userId: string,
    authenticationSucceeded: boolean,
    options?: EvaluationOptions,
  ): Promise<PolicyEvaluationResult<LockoutDecisionCode>> {
    const { trace, add } = createTraceCollector(options?.trace);
    const now = Date.now();
    const lockoutDurationMs = this.config.lockoutDurationMinutes * 60 * 1000;
    const current =
      (await this.store.getState(userId)) ?? ({ consecutiveFailures: 0 } as PasswordLockoutState);
    const lockoutUntilMs = current.lockoutUntil
      ? new Date(current.lockoutUntil).getTime()
      : Number.NaN;

    if (Number.isFinite(lockoutUntilMs) && lockoutUntilMs > now) {
      add("lockoutWindow", false, {
        lockoutUntil: new Date(lockoutUntilMs).toISOString(),
      });

      return withTrace(
        {
          success: false,
          reason: "ACCOUNT_TEMPORARILY_LOCKED",
          meta: {
            lockoutUntil: new Date(lockoutUntilMs).toISOString(),
            consecutiveFailures: current.consecutiveFailures,
          },
        },
        trace,
      );
    }

    if (authenticationSucceeded) {
      add("authenticationAttempt", true);

      if (this.config.resetOnSuccess) {
        await this.store.setState(userId, { consecutiveFailures: 0 });
        add("resetFailures", true);
      }

      return withTrace({ success: true }, trace);
    }

    const consecutiveFailures = current.consecutiveFailures + 1;
    add("authenticationAttempt", false, { consecutiveFailures });

    if (consecutiveFailures >= this.config.maxFailedAttempts) {
      const nextLockoutUntil = new Date(now + lockoutDurationMs).toISOString();
      await this.store.setState(userId, {
        consecutiveFailures,
        lockoutUntil: nextLockoutUntil,
      });
      add("lockoutApplied", false, {
        maxFailedAttempts: this.config.maxFailedAttempts,
        lockoutUntil: nextLockoutUntil,
      });

      return withTrace(
        {
          success: false,
          reason: "ACCOUNT_TEMPORARILY_LOCKED",
          meta: {
            consecutiveFailures,
            lockoutUntil: nextLockoutUntil,
            maxFailedAttempts: this.config.maxFailedAttempts,
          },
        },
        trace,
      );
    }

    await this.store.setState(userId, { consecutiveFailures });
    add("persistFailureCounter", true, { consecutiveFailures });

    return withTrace({ success: true }, trace);
  }
}

export class IdentityPolicyEngine {
  public constructor(
    private readonly deps: {
      complexity: PasswordComplexityEngine;
      rotation: PasswordRotationEngine;
      expiry: PasswordExpiryEngine;
    },
  ) {}

  public async validateComplexity(
    password: string,
    options?: EvaluationOptions,
  ): Promise<PolicyEvaluationResult<PasswordValidationCode>> {
    return this.deps.complexity.evaluate(password, options);
  }

  public async validateRotation(
    plainPassword: string,
    userId: string,
    comparator: RotationComparator,
    options?: EvaluationOptions,
  ): Promise<PolicyEvaluationResult<PasswordValidationCode>> {
    return this.deps.rotation.evaluate(plainPassword, userId, comparator, options);
  }

  public async validateExpiry(
    passwordCreatedAt: Date | string,
    options?: EvaluationOptions,
  ): Promise<PolicyEvaluationResult<PasswordValidationCode>> {
    return this.deps.expiry.evaluate(passwordCreatedAt, options);
  }
}

export type PasswordCreatedAtInput = Date | string;

export type PasswordUnicodeNormalizationForm = "NFC" | "NFD" | "NFKC" | "NFKD";

export type PolicyDecision<TReason extends string = string> =
  | { success: true }
  | {
      success: false;
      reason: TReason;
      meta?: Readonly<Record<string, unknown>>;
    };

export type PolicyTraceStep = {
  step: string;
  success: boolean;
  meta?: Readonly<Record<string, unknown>>;
};

export type PolicyEvaluationResult<TReason extends string> = PolicyDecision<TReason> & {
  trace?: PolicyTraceStep[];
};

export interface PasswordPolicyConfig {
  minLength?: number;
  maxLength?: number;
  normalizeTrim?: boolean;
  normalizeUnicode?: boolean;
  unicodeNormalizationForm?: PasswordUnicodeNormalizationForm;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSymbols?: boolean;
  denyList?: string[];
  preventRepeatedChars?: boolean;
  maxRepeatedChars?: number;
  preventSequentialChars?: boolean;
  maxSequentialChars?: number;
  expiryDays?: number;
  expiryWarningDays?: number;
  gracePeriodDays?: number;
  minimumPasswordAgeDays?: number;
  historyLimit?: number;
  blockSubstringsFromPreviousSecrets?: boolean;
  minPreviousSecretSubstringLength?: number;
}

export type PasswordExpiryState = "valid" | "warning" | "expired" | "grace";

export interface PasswordExpiryStateResult {
  state: PasswordExpiryState;
  daysUntilExpiry: number;
  daysRemainingInGracePeriod: number;
}

export interface PasswordPersistenceCallbacks {
  getPasswordHistory(userId: string): Promise<string[]>;
  saveNewPassword(userId: string, newHash: string): Promise<void>;
  getPreviousPasswordSubstrings?(userId: string): Promise<string[]>;
}

export type PasswordAuditEventType =
  | "complexity"
  | "rotation"
  | "expiry"
  | "minimumPasswordAge"
  | "gracePeriod"
  | "utcCalendar";

export interface PasswordAuditEvent {
  type: PasswordAuditEventType;
  userId?: string;
  outcome: "pass" | "fail" | "info";
  details?: Record<string, unknown>;
}

export type PasswordAuditEventCallback = (
  event: PasswordAuditEvent,
) => Promise<void> | void;

export type PasswordValidationIssueCode =
  | "PASSWORD_TOO_SHORT"
  | "PASSWORD_TOO_LONG"
  | "PASSWORD_MISSING_UPPERCASE"
  | "PASSWORD_MISSING_LOWERCASE"
  | "PASSWORD_MISSING_NUMBER"
  | "PASSWORD_MISSING_SYMBOL"
  | "PASSWORD_DENY_LISTED_PATTERN"
  | "PASSWORD_REPEATED_CONSECUTIVE_CHARS"
  | "PASSWORD_SEQUENTIAL_CHAR_RUN"
  | "PASSWORD_ENTROPY_TOO_LOW"
  | "PASSWORD_COMPROMISED";

export interface PasswordValidationIssue {
  code: PasswordValidationIssueCode;
  message: string;
  meta?: Record<string, unknown>;
}

export interface PasswordEntropyValidationContext {
  password: string;
  normalizedPassword: string;
}

export interface PasswordEntropyValidationResult {
  isValid: boolean;
  score?: number;
  details?: Record<string, unknown>;
}

export type PasswordEntropyValidator = (
  context: PasswordEntropyValidationContext,
) => Promise<PasswordEntropyValidationResult> | PasswordEntropyValidationResult;

export interface PasswordCompromisedPasswordValidationContext {
  password: string;
  normalizedPassword: string;
}

export interface PasswordCompromisedPasswordValidationResult {
  isCompromised: boolean;
  details?: Record<string, unknown>;
}

export type PasswordCompromisedPasswordValidator = (
  context: PasswordCompromisedPasswordValidationContext,
) =>
  | Promise<boolean | PasswordCompromisedPasswordValidationResult>
  | boolean
  | PasswordCompromisedPasswordValidationResult;

export interface IdentityPolicyEngineOptions extends PasswordPolicyConfig {
  persistence: PasswordPersistenceCallbacks;
  auditEventCallback?: PasswordAuditEventCallback;
  entropyValidator?: PasswordEntropyValidator;
  compromisedPasswordValidator?: PasswordCompromisedPasswordValidator;
}

export interface ComplexityValidationResult {
  isValid: boolean;
  errors: string[];
  issues?: PasswordValidationIssue[];
}

export type PasswordCompareFn = (
  data: string | Uint8Array,
  encrypted: string,
) => Promise<boolean>;

export interface PasswordHistoryComparisonContext {
  userId: string;
  plainPassword: string;
  normalizedPassword: string;
  history: readonly string[];
  historyLimit: number;
}

export interface PasswordHistoryComparisonStrategy {
  isReused(context: PasswordHistoryComparisonContext): Promise<boolean>;
}

export type PasswordHistoryComparator =
  | PasswordCompareFn
  | PasswordHistoryComparisonStrategy;

export type BulkPasswordHistoryCompareFn = (
  data: string | Uint8Array,
  history: readonly string[],
  context: Omit<
    PasswordHistoryComparisonContext,
    "history" | "normalizedPassword"
  >,
) => Promise<boolean>;

export interface PasswordSubjectContext {
  userId: string;
  passwordCreatedAt: Date;
}

export type GetUserIdAndDateFn<TRequest> = (
  request: TRequest,
) => Promise<PasswordSubjectContext>;

export interface ExpiryRejectionPayload {
  code: "PASSWORD_EXPIRED";
}

export interface GenericExpiryMiddlewareContext<TRequest> {
  request: TRequest;
  subject: PasswordSubjectContext;
  payload: ExpiryRejectionPayload;
}

export interface GenericExpiryGuardOptions<TRequest, TExpiredResult = unknown> {
  getUserIdAndDateFn: GetUserIdAndDateFn<TRequest>;
  isPasswordExpired: (passwordCreatedAt: Date) => boolean;
  onExpired: (
    context: GenericExpiryMiddlewareContext<TRequest>,
  ) => Promise<TExpiredResult> | TExpiredResult;
}

export type PipelineNextFn = (error?: unknown) => void;

export interface StatusJsonResponseLike {
  status(code: number): {
    json(body: unknown): unknown;
  };
}

export interface CreateStatusJsonExpiryMiddlewareOptions<
  TRequest = unknown,
  TResponse extends StatusJsonResponseLike = StatusJsonResponseLike,
> {
  getUserIdAndDateFn: GetUserIdAndDateFn<TRequest>;
  isPasswordExpired: (passwordCreatedAt: Date) => boolean;
  buildExpiredPayload?: () => ExpiryRejectionPayload;
  onForbidden?: (
    response: TResponse,
    payload: ExpiryRejectionPayload,
  ) => unknown;
}

export interface CodeSendReplyLike {
  code(statusCode: number): {
    send(payload: unknown): unknown;
  };
}

export interface CreateCodeSendExpiryHookOptions<
  TRequest = unknown,
  TReply extends CodeSendReplyLike = CodeSendReplyLike,
> {
  getUserIdAndDateFn: GetUserIdAndDateFn<TRequest>;
  isPasswordExpired: (passwordCreatedAt: Date) => boolean;
  buildExpiredPayload?: () => ExpiryRejectionPayload;
  onForbidden?: (reply: TReply, payload: ExpiryRejectionPayload) => unknown;
}

export type StatusJsonExpiryMiddleware<
  TRequest = unknown,
  TResponse extends StatusJsonResponseLike = StatusJsonResponseLike,
> = (
  request: TRequest,
  response: TResponse,
  next: PipelineNextFn,
) => Promise<void>;

export type CodeSendExpiryHook<
  TRequest = unknown,
  TReply extends CodeSendReplyLike = CodeSendReplyLike,
> = (request: TRequest, reply: TReply) => Promise<void>;

export interface ResolvedIdentityPolicyEngineOptions extends Required<PasswordPolicyConfig> {
  persistence: PasswordPersistenceCallbacks;
  auditEventCallback?: PasswordAuditEventCallback;
  entropyValidator?: PasswordEntropyValidator;
  compromisedPasswordValidator?: PasswordCompromisedPasswordValidator;
}

export type PolicyValidationSuccess = { valid: true };

export type PolicyValidationFailure<TReason extends string> = {
  valid: false;
  reason: TReason;
  details?: Record<string, unknown>;
};

export type PolicyValidationOutcome<TReason extends string> =
  | PolicyValidationSuccess
  | PolicyValidationFailure<TReason>;

export type PasswordRotationFailureReason =
  | "PASSWORD_REUSED"
  | "PASSWORD_CONTAINS_PREVIOUS_SUBSTRING";

export type PasswordRotationValidationOutcome =
  PolicyValidationOutcome<PasswordRotationFailureReason>;

export type MinimumPasswordAgeFailureReason = "MINIMUM_PASSWORD_AGE_NOT_SATISFIED";

export type MinimumPasswordAgeValidationOutcome =
  PolicyValidationOutcome<MinimumPasswordAgeFailureReason>;

export type PasswordComplexityValidationOutcome = PolicyValidationSuccess | {
  valid: false;
  reasons: PasswordValidationIssue[];
  details?: Record<string, unknown>;
};
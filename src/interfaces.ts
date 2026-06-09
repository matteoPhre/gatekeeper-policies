export type PasswordCreatedAtInput = Date | string;

export type PasswordUnicodeNormalizationForm = "NFC" | "NFD" | "NFKC" | "NFKD";

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

export interface IdentityPolicyEngineOptions extends PasswordPolicyConfig {
    persistence: PasswordPersistenceCallbacks;
}

export interface ComplexityValidationResult {
    isValid: boolean;
    errors: string[];
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
    context: Omit<PasswordHistoryComparisonContext, "history" | "normalizedPassword">,
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
    onForbidden?: (response: TResponse, payload: ExpiryRejectionPayload) => unknown;
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

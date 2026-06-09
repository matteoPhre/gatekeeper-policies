import {
    type BulkPasswordHistoryCompareFn,
    type ComplexityValidationResult,
    type PasswordHistoryComparator,
    type PasswordHistoryComparisonStrategy,
    type IdentityPolicyEngineOptions,
    type PasswordCompareFn,
    type PasswordCreatedAtInput,
    type PasswordPersistenceCallbacks,
    type PasswordPolicyConfig,
    type PasswordUnicodeNormalizationForm,
} from "./interfaces";

const MS_PER_DAY = 24 * 60 * 60 * 1000;

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
    minimumPasswordAgeDays: 0,
    historyLimit: 5,
    blockSubstringsFromPreviousSecrets: false,
    minPreviousSecretSubstringLength: 4,
};

export interface ResolvedIdentityPolicyEngineOptions
    extends Required<PasswordPolicyConfig> {
    persistence: PasswordPersistenceCallbacks;
}

export class IdentityPolicyEngine {
    private readonly config: ResolvedIdentityPolicyEngineOptions;

    public constructor(options: IdentityPolicyEngineOptions) {
        this.config = resolveEngineOptions(options);
    }

    public getConfig(): Readonly<ResolvedIdentityPolicyEngineOptions> {
        return this.config;
    }

    public validateComplexity(password: string): ComplexityValidationResult {
        const errors: string[] = [];
        const normalizedPassword = normalizePasswordInput(password, this.config);

        if (normalizedPassword.length < this.config.minLength) {
            errors.push(`Password must be at least ${this.config.minLength} characters long.`);
        }

        if (normalizedPassword.length > this.config.maxLength) {
            errors.push(`Password must be at most ${this.config.maxLength} characters long.`);
        }

        if (this.config.requireUppercase && !/[A-Z]/.test(normalizedPassword)) {
            errors.push("Password must include at least one uppercase letter.");
        }

        if (this.config.requireLowercase && !/[a-z]/.test(normalizedPassword)) {
            errors.push("Password must include at least one lowercase letter.");
        }

        if (this.config.requireNumbers && !/[0-9]/.test(normalizedPassword)) {
            errors.push("Password must include at least one number.");
        }

        if (
            this.config.requireSymbols
            && !/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(normalizedPassword)
        ) {
            errors.push("Password must include at least one symbol.");
        }

        if (isInDenyList(normalizedPassword, this.config.denyList, this.config)) {
            errors.push("Password contains a denied pattern.");
        }

        if (
            this.config.preventRepeatedChars
            && hasRepeatedChars(normalizedPassword, this.config.maxRepeatedChars)
        ) {
            errors.push(
                `Password must not contain more than ${this.config.maxRepeatedChars} repeated consecutive characters.`,
            );
        }

        if (
            this.config.preventSequentialChars
            && hasSequentialChars(normalizedPassword, this.config.maxSequentialChars)
        ) {
            errors.push(
                `Password must not contain sequential character runs of length ${this.config.maxSequentialChars} or more.`,
            );
        }

        return {
            isValid: errors.length === 0,
            errors,
        };
    }

    public async validateRotation(
        plainPassword: string,
        userId: string,
        comparator: PasswordHistoryComparator,
    ): Promise<boolean> {
        const normalizedPlainPassword = normalizePasswordInput(plainPassword, this.config);

        if (this.config.blockSubstringsFromPreviousSecrets) {
            const previousSubstrings = await this.config.persistence.getPreviousPasswordSubstrings?.(userId);

            if (hasBlockedPreviousSecretSubstring(normalizedPlainPassword, previousSubstrings, this.config)) {
                return false;
            }
        }

        const history = await this.config.persistence.getPasswordHistory(userId);
        const limitedHistory = history.slice(0, this.config.historyLimit);

        if (!isPasswordCompareFn(comparator)) {
            const isReused = await comparator.isReused({
                userId,
                plainPassword,
                normalizedPassword: normalizedPlainPassword,
                history: limitedHistory,
                historyLimit: this.config.historyLimit,
            });

            return !isReused;
        }

        for (const previousHash of limitedHistory) {
            const isReused = await comparator(normalizedPlainPassword, previousHash);
            if (isReused) {
                return false;
            }
        }

        return true;
    }

    public isPasswordExpired(passwordCreatedAt: PasswordCreatedAtInput): boolean {
        const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
        const now = Date.now();
        const ageInMs = now - createdAt.getTime();
        const maxAgeInMs = this.config.expiryDays * MS_PER_DAY;

        return ageInMs >= maxAgeInMs;
    }

    public daysUntilExpiry(passwordCreatedAt: PasswordCreatedAtInput): number {
        const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
        const now = Date.now();
        const ageInMs = now - createdAt.getTime();
        const maxAgeInMs = this.config.expiryDays * MS_PER_DAY;
        const remainingMs = maxAgeInMs - ageInMs;

        if (remainingMs <= 0) {
            return 0;
        }

        return Math.ceil(remainingMs / MS_PER_DAY);
    }

    public isMinimumPasswordAgeSatisfied(passwordCreatedAt: PasswordCreatedAtInput): boolean {
        if (this.config.minimumPasswordAgeDays === 0) {
            return true;
        }

        const createdAt = normalizePasswordCreatedAt(passwordCreatedAt);
        const now = Date.now();
        const ageInMs = now - createdAt.getTime();
        const minimumAgeInMs = this.config.minimumPasswordAgeDays * MS_PER_DAY;

        return ageInMs >= minimumAgeInMs;
    }
}

export function normalizePasswordCreatedAt(passwordCreatedAt: PasswordCreatedAtInput): Date {
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

function resolveEngineOptions(
    options: IdentityPolicyEngineOptions,
): ResolvedIdentityPolicyEngineOptions {
    if (!options || !options.persistence) {
        throw new TypeError("IdentityPolicyEngine requires persistence callbacks.");
    }

    const config: ResolvedIdentityPolicyEngineOptions = {
        minLength: options.minLength ?? DEFAULT_POLICY_CONFIG.minLength,
        maxLength: options.maxLength ?? DEFAULT_POLICY_CONFIG.maxLength,
        normalizeTrim: options.normalizeTrim ?? DEFAULT_POLICY_CONFIG.normalizeTrim,
        normalizeUnicode: options.normalizeUnicode ?? DEFAULT_POLICY_CONFIG.normalizeUnicode,
        unicodeNormalizationForm:
            options.unicodeNormalizationForm ?? DEFAULT_POLICY_CONFIG.unicodeNormalizationForm,
        requireUppercase: options.requireUppercase ?? DEFAULT_POLICY_CONFIG.requireUppercase,
        requireLowercase: options.requireLowercase ?? DEFAULT_POLICY_CONFIG.requireLowercase,
        requireNumbers: options.requireNumbers ?? DEFAULT_POLICY_CONFIG.requireNumbers,
        requireSymbols: options.requireSymbols ?? DEFAULT_POLICY_CONFIG.requireSymbols,
        denyList: options.denyList ?? DEFAULT_POLICY_CONFIG.denyList,
        preventRepeatedChars: options.preventRepeatedChars ?? DEFAULT_POLICY_CONFIG.preventRepeatedChars,
        maxRepeatedChars: options.maxRepeatedChars ?? DEFAULT_POLICY_CONFIG.maxRepeatedChars,
        preventSequentialChars: options.preventSequentialChars ?? DEFAULT_POLICY_CONFIG.preventSequentialChars,
        maxSequentialChars: options.maxSequentialChars ?? DEFAULT_POLICY_CONFIG.maxSequentialChars,
        expiryDays: options.expiryDays ?? DEFAULT_POLICY_CONFIG.expiryDays,
        minimumPasswordAgeDays:
            options.minimumPasswordAgeDays ?? DEFAULT_POLICY_CONFIG.minimumPasswordAgeDays,
        historyLimit: options.historyLimit ?? DEFAULT_POLICY_CONFIG.historyLimit,
        blockSubstringsFromPreviousSecrets:
            options.blockSubstringsFromPreviousSecrets
            ?? DEFAULT_POLICY_CONFIG.blockSubstringsFromPreviousSecrets,
        minPreviousSecretSubstringLength:
            options.minPreviousSecretSubstringLength
            ?? DEFAULT_POLICY_CONFIG.minPreviousSecretSubstringLength,
        persistence: options.persistence,
    };

    if (!Number.isInteger(config.minLength) || config.minLength < 1) {
        throw new RangeError("minLength must be an integer greater than 0.");
    }

    if (!Number.isInteger(config.maxLength) || config.maxLength < 1) {
        throw new RangeError("maxLength must be an integer greater than 0.");
    }

    if (config.maxLength < config.minLength) {
        throw new RangeError("maxLength must be greater than or equal to minLength.");
    }

    if (!Array.isArray(config.denyList)) {
        throw new TypeError("denyList must be an array of strings.");
    }

    if (config.denyList.some((entry) => typeof entry !== "string")) {
        throw new TypeError("denyList must contain only strings.");
    }

    if (!Number.isInteger(config.maxRepeatedChars) || config.maxRepeatedChars < 2) {
        throw new RangeError("maxRepeatedChars must be an integer greater than or equal to 2.");
    }

    if (!Number.isInteger(config.maxSequentialChars) || config.maxSequentialChars < 2) {
        throw new RangeError("maxSequentialChars must be an integer greater than or equal to 2.");
    }

    if (!isValidUnicodeNormalizationForm(config.unicodeNormalizationForm)) {
        throw new RangeError(
            "unicodeNormalizationForm must be one of NFC, NFD, NFKC, NFKD.",
        );
    }

    if (!Number.isInteger(config.expiryDays) || config.expiryDays < 1) {
        throw new RangeError("expiryDays must be an integer greater than 0.");
    }

    if (!Number.isInteger(config.minimumPasswordAgeDays) || config.minimumPasswordAgeDays < 0) {
        throw new RangeError("minimumPasswordAgeDays must be a non-negative integer.");
    }

    if (!Number.isInteger(config.historyLimit) || config.historyLimit < 1) {
        throw new RangeError("historyLimit must be an integer greater than 0.");
    }

    if (
        !Number.isInteger(config.minPreviousSecretSubstringLength)
        || config.minPreviousSecretSubstringLength < 1
    ) {
        throw new RangeError("minPreviousSecretSubstringLength must be an integer greater than 0.");
    }

    if (
        config.blockSubstringsFromPreviousSecrets
        && typeof config.persistence.getPreviousPasswordSubstrings !== "function"
    ) {
        throw new TypeError(
            "getPreviousPasswordSubstrings persistence callback is required when blockSubstringsFromPreviousSecrets is enabled.",
        );
    }

    return config;
}

function isInDenyList(
    password: string,
    denyList: string[],
    config: ResolvedIdentityPolicyEngineOptions,
): boolean {
    const normalizedPassword = password.toLowerCase();
    return denyList.some((entry) => {
        const normalizedEntry = normalizePasswordInput(entry, config).trim().toLowerCase();
        return normalizedEntry.length > 0 && normalizedPassword.includes(normalizedEntry);
    });
}

function normalizePasswordInput(
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
        normalizedValue = normalizedValue.normalize(config.unicodeNormalizationForm);
    }

    return normalizedValue;
}

function isValidUnicodeNormalizationForm(value: string): value is PasswordUnicodeNormalizationForm {
    return value === "NFC" || value === "NFD" || value === "NFKC" || value === "NFKD";
}

function isPasswordCompareFn(comparator: PasswordHistoryComparator): comparator is PasswordCompareFn {
    return typeof comparator === "function";
}

function hasBlockedPreviousSecretSubstring(
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
        const normalizedEntry = normalizePasswordInput(entry, config).trim().toLowerCase();

        return (
            normalizedEntry.length >= config.minPreviousSecretSubstringLength
            && candidate.includes(normalizedEntry)
        );
    });
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

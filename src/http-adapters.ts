import {
  type CodeSendExpiryHook,
  type CodeSendReplyLike,
  type CreateCodeSendExpiryHookOptions,
  type CreateStatusJsonExpiryMiddlewareOptions,
  type ExpiryRejectionPayload,
  type GenericExpiryGuardOptions,
  type PasswordSubjectContext,
  type PipelineNextFn,
  type StatusJsonExpiryMiddleware,
  type StatusJsonResponseLike,
} from "./interfaces";

const EXPIRED_PAYLOAD: ExpiryRejectionPayload = { code: "PASSWORD_EXPIRED" };

function getExpiredPayload(
  payloadFactory?: () => ExpiryRejectionPayload,
): ExpiryRejectionPayload {
  return payloadFactory ? payloadFactory() : EXPIRED_PAYLOAD;
}

export async function evaluatePasswordExpiry<
  TRequest,
  TExpiredResult = unknown,
>(
  request: TRequest,
  options: GenericExpiryGuardOptions<TRequest, TExpiredResult>,
): Promise<{
  expired: boolean;
  subject: PasswordSubjectContext;
  expiredResult?: TExpiredResult;
}> {
  const subject = await options.getUserIdAndDateFn(request);
  const expired = options.isPasswordExpired(subject.passwordCreatedAt);

  if (!expired) {
    return { expired: false, subject };
  }

  const payload: ExpiryRejectionPayload = { code: "PASSWORD_EXPIRED" };
  const expiredResult = await options.onExpired({
    request,
    subject,
    payload,
  });

  return {
    expired: true,
    subject,
    expiredResult,
  };
}

export function createStatusJsonExpiryMiddleware<
  TRequest = unknown,
  TResponse extends StatusJsonResponseLike = StatusJsonResponseLike,
>(
  options: CreateStatusJsonExpiryMiddlewareOptions<TRequest, TResponse>,
): StatusJsonExpiryMiddleware<TRequest, TResponse> {
  return async (
    request: TRequest,
    response: TResponse,
    next: PipelineNextFn,
  ): Promise<void> => {
    try {
      const subject = await options.getUserIdAndDateFn(request);
      const expired = options.isPasswordExpired(subject.passwordCreatedAt);

      if (expired) {
        const payload = getExpiredPayload(options.buildExpiredPayload);

        if (options.onForbidden) {
          options.onForbidden(response, payload);
          return;
        }

        response.status(403).json(payload);
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

export function createCodeSendExpiryHook<
  TRequest = unknown,
  TReply extends CodeSendReplyLike = CodeSendReplyLike,
>(
  options: CreateCodeSendExpiryHookOptions<TRequest, TReply>,
): CodeSendExpiryHook<TRequest, TReply> {
  return async (request: TRequest, reply: TReply): Promise<void> => {
    const subject = await options.getUserIdAndDateFn(request);
    const expired = options.isPasswordExpired(subject.passwordCreatedAt);

    if (!expired) {
      return;
    }

    const payload = getExpiredPayload(options.buildExpiredPayload);

    if (options.onForbidden) {
      options.onForbidden(reply, payload);
      return;
    }

    reply.code(403).send(payload);
  };
}

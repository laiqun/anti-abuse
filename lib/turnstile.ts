// Cloudflare Turnstile server-side verification.
// https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
//
// The site key is public (rendered by the widget); the secret key lives in
// admin settings (`turnstile_secret_key`) or the TURNSTILE_SECRET_KEY env var.
// Callers resolve the secret and pass it in — this file has no config access.

export const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

/** Header the client may use instead of a body field. */
export const TURNSTILE_TOKEN_HEADER = 'cf-turnstile-response';

/** Body field name used by the official widget form integration. */
export const TURNSTILE_TOKEN_FIELD = 'cf-turnstile-response';

export interface TurnstileVerifyResult {
  success: boolean;
  /** Cloudflare error codes, e.g. "timeout-or-duplicate", "invalid-input-response". */
  errorCodes: string[];
  action?: string;
  hostname?: string;
  challengeTs?: string;
}

interface SiteverifyResponse {
  success: boolean;
  'error-codes'?: string[];
  action?: string;
  hostname?: string;
  challenge_ts?: string;
}

/** Pull the token from the header or an explicit value (body field). */
export function getTurnstileToken(request: Request, explicit?: string | null): string | undefined {
  const raw = (explicit ?? request.headers.get(TURNSTILE_TOKEN_HEADER) ?? '').trim();
  // Tokens are opaque strings up to 2048 chars per Cloudflare docs.
  if (!raw || raw.length > 2048) return undefined;
  return raw;
}

/**
 * Verify a Turnstile token. Never throws: network or parse failures return
 * `success: false` with an `internal-error` code so callers fail closed.
 *
 * `expectedAction` / `expectedHostname` tighten the check when the widget
 * was rendered with a specific `action` (recommended: one per entrypoint,
 * e.g. "signup", "login", "otp", "submit").
 */
export async function verifyTurnstileToken(params: {
  secret: string;
  token: string;
  remoteIp?: string;
  expectedAction?: string;
  expectedHostname?: string;
  fetchImpl?: typeof fetch;
}): Promise<TurnstileVerifyResult> {
  const { secret, token, remoteIp, expectedAction, expectedHostname } = params;
  const fetchImpl = params.fetchImpl ?? fetch;

  if (!secret) return { success: false, errorCodes: ['missing-input-secret'] };
  if (!token) return { success: false, errorCodes: ['missing-input-response'] };

  const body = new URLSearchParams({ secret, response: token });
  if (remoteIp) body.set('remoteip', remoteIp);

  let data: SiteverifyResponse;
  try {
    const res = await fetchImpl(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    data = (await res.json()) as SiteverifyResponse;
  } catch {
    return { success: false, errorCodes: ['internal-error'] };
  }

  const result: TurnstileVerifyResult = {
    success: Boolean(data.success),
    errorCodes: data['error-codes'] ?? [],
    action: data.action,
    hostname: data.hostname,
    challengeTs: data.challenge_ts,
  };

  if (result.success && expectedAction && result.action !== expectedAction) {
    return { ...result, success: false, errorCodes: ['action-mismatch'] };
  }
  if (result.success && expectedHostname && result.hostname !== expectedHostname) {
    return { ...result, success: false, errorCodes: ['hostname-mismatch'] };
  }
  return result;
}

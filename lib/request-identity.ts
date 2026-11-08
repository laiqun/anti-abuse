// Request-level identity signals used by the anti-abuse tools: client IP,
// country (Cloudflare edge header) and a device fingerprint.
//
// None of these are trustworthy on their own (see the dedup matrix in
// src/modules/anti-abuse/service.ts); they are only meaningful combined with
// the server-issued anon_id cookie (src/lib/anon-id.ts) or the user's email.

/** Header the client may use to send a FingerprintJS-style visitor id. */
export const FINGERPRINT_HEADER = 'x-device-fingerprint';

/** Countries that never receive free credits (ISO 3166-1 alpha-2). */
export const DEFAULT_NO_BONUS_COUNTRIES: readonly string[] = ['IN'];

export interface RequestIdentity {
  /** Client IP, '' when unknown (local dev without a proxy). */
  ip: string;
  /** Upper-case ISO country from cf-ipcountry, null when unknown. */
  country: string | null;
  userAgent: string;
  /**
   * sha256 of the client-supplied fingerprint, or of a UA-based fallback when
   * the client sent none. `fingerprintSource` tells which one it was — the
   * fallback is much weaker and should be treated as "probably same browser"
   * at best.
   */
  fingerprint: string;
  fingerprintSource: 'client' | 'fallback';
}

export function getClientIp(request: Request): string {
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf.trim();
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0]?.trim() || '';
  return request.headers.get('x-real-ip')?.trim() || '';
}

export function getClientCountry(request: Request): string | null {
  const country = request.headers.get('cf-ipcountry')?.trim().toUpperCase();
  // Cloudflare sends XX for unknown and T1 for Tor exit nodes.
  if (!country || country === 'XX' || country === 'T1') return null;
  return country;
}

export function isNoBonusCountry(
  country: string | null | undefined,
  list: readonly string[] = DEFAULT_NO_BONUS_COUNTRIES
): boolean {
  if (!country) return false;
  return list.includes(country.toUpperCase());
}

/** Parse a comma-separated country list from admin config ("IN, PK"). */
export function parseCountryList(value: string | undefined): string[] {
  if (!value) return [...DEFAULT_NO_BONUS_COUNTRIES];
  return value
    .split(',')
    .map((c) => c.trim().toUpperCase())
    .filter((c) => /^[A-Z]{2}$/.test(c));
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Read the client fingerprint from the request header or an explicit value
 * (e.g. a body field). Capped in length: it is client-controlled input.
 */
export function getClientFingerprint(request: Request, explicit?: string | null): string | undefined {
  const raw = (explicit ?? request.headers.get(FINGERPRINT_HEADER) ?? '').trim();
  if (!raw || raw.length > 128) return undefined;
  return raw;
}

/**
 * Collect ip / country / fingerprint for a request. When the client sent no
 * fingerprint, derive a weak one from stable request headers so the dedup
 * logic still has something to compare.
 */
export async function getRequestIdentity(
  request: Request,
  opts: { fingerprint?: string | null } = {}
): Promise<RequestIdentity> {
  const ip = getClientIp(request);
  const country = getClientCountry(request);
  const userAgent = request.headers.get('user-agent') ?? '';
  const clientFp = getClientFingerprint(request, opts.fingerprint);

  if (clientFp) {
    return {
      ip,
      country,
      userAgent,
      fingerprint: await sha256Hex(`fp:${clientFp}`),
      fingerprintSource: 'client',
    };
  }

  const fallbackParts = [
    userAgent,
    request.headers.get('accept-language') ?? '',
    request.headers.get('sec-ch-ua') ?? '',
    request.headers.get('sec-ch-ua-platform') ?? '',
  ];
  return {
    ip,
    country,
    userAgent,
    fingerprint: await sha256Hex(`ua:${fallbackParts.join('|')}`),
    fingerprintSource: 'fallback',
  };
}

// Email checks for the sign-up / OTP entrypoints: a domain whitelist and a
// canonical form used as the dedup key for "one free grant per email".
//
// normalizeEmail is a *comparison key only* — never write it back to the user
// row (a previous attempt to rewrite stored emails was reverted).

export const GMAIL_DOMAINS: readonly string[] = ['gmail.com', 'googlemail.com'];

/** Default whitelist for email/password sign-up: only Gmail. */
export const DEFAULT_ALLOWED_EMAIL_DOMAINS: readonly string[] = GMAIL_DOMAINS;

export type EmailPolicyReason = 'invalid' | 'domain_blocked' | 'domain_not_allowed';

export interface EmailPolicyResult {
  ok: boolean;
  reason?: EmailPolicyReason;
  domain?: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
  const value = email.trim();
  // RFC 5321 caps an address at 254 chars; also bounds regex backtracking
  // on attacker-supplied input.
  return value.length <= 254 && EMAIL_RE.test(value);
}

export function getEmailDomain(email: string): string {
  const value = email.trim().toLowerCase();
  const at = value.lastIndexOf('@');
  return at <= 0 ? '' : value.slice(at + 1);
}

/**
 * Canonical dedup key: lower-cased; for Gmail the dots and the "+tag" suffix
 * are removed (a.b+x@gmail.com and ab@gmail.com are the same inbox). Other
 * providers only get the "+tag" stripped.
 */
export function normalizeEmail(email: string): string {
  const value = email.trim().toLowerCase();
  const at = value.lastIndexOf('@');
  if (at <= 0) return value;

  let local = value.slice(0, at);
  let domain = value.slice(at + 1);

  const plus = local.indexOf('+');
  if (plus !== -1) local = local.slice(0, plus);

  if (GMAIL_DOMAINS.includes(domain)) {
    local = local.replaceAll('.', '');
    domain = 'gmail.com';
  }
  return `${local}@${domain}`;
}

/** Parse a comma/newline separated domain list from admin config. */
export function parseDomainList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(/[,\n]/)
    .map((d) => d.trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean);
}

/**
 * Whitelist / blocklist check. An empty `allowedDomains` means "any domain",
 * `blockedDomains` always wins.
 */
export function checkEmailPolicy(
  email: string,
  opts: { allowedDomains?: readonly string[]; blockedDomains?: readonly string[] } = {}
): EmailPolicyResult {
  if (!isValidEmail(email)) return { ok: false, reason: 'invalid' };
  const domain = getEmailDomain(email);

  if (opts.blockedDomains?.includes(domain)) {
    return { ok: false, reason: 'domain_blocked', domain };
  }
  if (opts.allowedDomains && opts.allowedDomains.length > 0 && !opts.allowedDomains.includes(domain)) {
    return { ok: false, reason: 'domain_not_allowed', domain };
  }
  return { ok: true, domain };
}

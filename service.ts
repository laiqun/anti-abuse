// Anti-abuse toolkit: persistent rate limits / cooldowns, free-credit grant
// dedup with decay, and a credit balance for anonymous visitors.
//
// Nothing here is wired into a route yet. Intended wiring (one entrypoint
// per row of the plan):
//   sign-up   → checkEmailPolicy + verifyTurnstileToken + hitRateLimit(SIGNUP_IP)
//               + grantAllowance(scene 'signup', subjectType 'email')
//   log-in    → verifyTurnstileToken + peekRateLimit/hitRateLimit(LOGIN_FAIL_*)
//   OTP       → verifyTurnstileToken + hitRateLimit(OTP_EMAIL / OTP_IP)
//   submit    → ensureAnonId + hitRateLimit(GUEST_SUBMIT) + consumeGuestCredits
//               (guests) or credits.consume (users)
//   grants    → grantAllowance / revokeGrant / getGrantTotals (daily caps)
//
// Registered users keep their balance in the `credit` table (credits module);
// this module only *decides* how much to grant and records the decision. The
// caller applies the grant (see `grantAllowance`'s `apply` callback) so this
// module never imports another module.

import { and, eq, gt, gte, inArray, isNull, or, sql } from 'drizzle-orm';

import { abuseRateLimit, grantRecord, guestQuota, type GrantRecord, type GuestQuota } from '@/config/db/schema';
import { db } from '@/core/db';
import { parseDomainList } from '@/lib/email-policy';
import { getUuid } from '@/lib/hash';
import { isNoBonusCountry, parseCountryList } from '@/lib/request-identity';

// ─── Settings ────────────────────────────────────────────────────────────────

/** Admin-config keys (see modules/config/settings.ts) with their defaults. */
export interface AntiAbuseSettings {
  /** Base free credits for an anonymous visitor (abuse_guest_credits). */
  guestCredits: number;
  /** Days before guest credits expire; 0 = never (abuse_guest_credits_valid_days). */
  guestCreditsValidDays: number;
  /** Floor used by the decay rule, "最小额度" (abuse_min_credits). */
  minCredits: number;
  /** After this many matched prior grants nothing more is given (abuse_max_repeat_grants). */
  maxRepeatGrants: number;
  /** Credits subtracted per prior matched grant (abuse_decay_step). */
  decayStep: number;
  /** Countries that never get free credits (abuse_no_bonus_countries). */
  noBonusCountries: string[];
  /** Sign-up email domain whitelist; empty = any (abuse_allowed_email_domains). */
  allowedEmailDomains: string[];
}

export function getAntiAbuseSettings(configs: Record<string, string | undefined>): AntiAbuseSettings {
  const num = (key: string, fallback: number) => {
    const v = parseInt(configs[key] ?? '', 10);
    return Number.isFinite(v) && v >= 0 ? v : fallback;
  };
  return {
    guestCredits: num('abuse_guest_credits', 10),
    guestCreditsValidDays: num('abuse_guest_credits_valid_days', 30),
    minCredits: num('abuse_min_credits', 1),
    maxRepeatGrants: num('abuse_max_repeat_grants', 3),
    decayStep: num('abuse_decay_step', 1),
    noBonusCountries: parseCountryList(configs.abuse_no_bonus_countries),
    allowedEmailDomains: parseDomainList(configs.abuse_allowed_email_domains),
  };
}

// ─── Rate limits / cooldowns ─────────────────────────────────────────────────
// Fixed-window counters stored in the database so they hold across Worker
// isolates (the in-memory src/lib/rate-limit.ts does not). One row per
// (scope, subject); `blockMs` turns an overflow into a hard block (brute-force).

export const RateLimitScope = {
  /** Sign-ups per IP (plan: block a second sign-up within 1 minute). */
  SIGNUP_IP: 'signup_ip',
  /** Failed logins per email / per IP; clear on success. */
  LOGIN_FAIL_EMAIL: 'login_fail_email',
  LOGIN_FAIL_IP: 'login_fail_ip',
  /** OTP / password-reset sends per email / per IP. */
  OTP_EMAIL: 'otp_email',
  OTP_IP: 'otp_ip',
  /** Task submissions by anonymous visitors (anon_id). */
  GUEST_SUBMIT: 'guest_submit',
  /** Task submissions by free registered users. */
  FREE_SUBMIT: 'free_submit',
} as const;

export interface RateLimitResult {
  allowed: boolean;
  /** Hits in the current window, including this one. */
  count: number;
  limit: number;
  /** Seconds until the window resets or the block lifts; 0 when allowed. */
  retryAfterSeconds: number;
  /** True when refused because of a hard block (`blockMs`). */
  blocked: boolean;
}

function rateLimitKey(scope: string, subject: string) {
  return `${scope}|${subject}`;
}

async function getRateLimitRow(key: string) {
  const [row] = await db().select().from(abuseRateLimit).where(eq(abuseRateLimit.key, key)).limit(1);
  return row;
}

function secondsUntil(date: Date, now: Date) {
  return Math.max(1, Math.ceil((date.getTime() - now.getTime()) / 1000));
}

/**
 * Count one hit and decide. `limit` hits are allowed per `windowMs`; the
 * (limit + 1)th is refused. With `blockMs`, overflowing also blocks the
 * subject for that long regardless of the window.
 *
 * A cooldown ("one action per N seconds") is `{ limit: 1, windowMs: N*1000 }`.
 *
 * `subject` is any string — the caller picks the dimension; `scope` names it.
 * RateLimitScope holds common names but new scopes are fine.
 *
 * Single dimension:
 *   hitRateLimit({ scope: 'guest_submit', subject: anonId,      limit: 5, windowMs: 3600_000 })
 *   hitRateLimit({ scope: 'otp_email',    subject: normEmail,   limit: 1, windowMs: 60_000 })
 *   hitRateLimit({ scope: 'signup_fp',    subject: fingerprint, limit: 3, windowMs: 86400_000 })
 *   hitRateLimit({ scope: 'signup_ip',    subject: ip,          limit: 1, windowMs: 60_000 })
 *
 * Combining — two forms with different meanings:
 *
 * 1. One joined subject = AND: only requests matching on ALL parts share a
 *    counter. Same device AND same ip; a new ip starts a fresh counter, so
 *    many devices behind one office ip don't crowd each other out.
 *      hitRateLimit({ scope: 'signup_fp_ip', subject: `${fingerprint}|${ip}`, limit: 2, windowMs: 3600_000 })
 *
 * 2. Separate calls = OR: refuse if ANY one is over. Changing the email
 *    doesn't escape the ip limit and vice versa — both must change. Stricter;
 *    usually what anti-abuse wants (e.g. OTP: per email AND per ip).
 *      const byEmail = await hitRateLimit({ scope: 'otp_email', subject: normEmail, limit: 1, windowMs: 60_000 });
 *      const byIp    = await hitRateLimit({ scope: 'otp_ip',    subject: ip,        limit: 5, windowMs: 60_000 });
 *      if (!byEmail.allowed || !byIp.allowed) { ...refuse }
 *
 * Caveats:
 * - In form 2 every call counts a hit, even when another dimension already
 *   refused. To avoid that, peekRateLimit all dimensions first and only
 *   hitRateLimit each one when all pass.
 * - Normalize emails (lib/email-policy normalizeEmail) before using them as
 *   the subject, or a.b+1@gmail.com and ab@gmail.com count separately.
 * - MySQL: the `key` column (`scope|subject`) is varchar(191). fingerprint
 *   (64) + ipv6 (≤45) fits, but an email can reach 254 chars — hash long or
 *   joined subjects with sha256Hex (lib/request-identity) first.
 *   sqlite / postgres use text and have no limit.
 */
export async function hitRateLimit(params: {
  scope: string;
  subject: string;
  limit: number;
  windowMs: number;
  blockMs?: number;
}): Promise<RateLimitResult> {
  const { scope, subject, limit, windowMs, blockMs } = params;
  const key = rateLimitKey(scope, subject);
  const now = new Date();

  let row = await getRateLimitRow(key);

  if (row?.blockedUntil && row.blockedUntil > now) {
    return { allowed: false, count: row.count, limit, retryAfterSeconds: secondsUntil(row.blockedUntil, now), blocked: true };
  }

  if (!row) {
    try {
      await db().insert(abuseRateLimit).values({ key, scope, subject, count: 1, windowStart: now, updatedAt: now });
      return { allowed: 1 <= limit, count: 1, limit, retryAfterSeconds: 0, blocked: false };
    } catch {
      // Lost the insert race — fall through to the increment path.
      row = await getRateLimitRow(key);
      if (!row) throw new Error('rate limit row vanished');
    }
  }

  if (now.getTime() - row.windowStart.getTime() >= windowMs) {
    await db()
      .update(abuseRateLimit)
      .set({ count: 1, windowStart: now, blockedUntil: null, updatedAt: now })
      .where(eq(abuseRateLimit.key, key));
    return { allowed: 1 <= limit, count: 1, limit, retryAfterSeconds: 0, blocked: false };
  }

  // Atomic increment; concurrent hits only push the count higher, which is
  // the conservative outcome for a limiter.
  await db()
    .update(abuseRateLimit)
    .set({ count: sql`${abuseRateLimit.count} + 1`, updatedAt: now })
    .where(eq(abuseRateLimit.key, key));
  const after = (await getRateLimitRow(key)) ?? row;
  const count = after.count;

  if (count <= limit) {
    return { allowed: true, count, limit, retryAfterSeconds: 0, blocked: false };
  }

  if (blockMs) {
    const blockedUntil = new Date(now.getTime() + blockMs);
    await db().update(abuseRateLimit).set({ blockedUntil }).where(eq(abuseRateLimit.key, key));
    return { allowed: false, count, limit, retryAfterSeconds: secondsUntil(blockedUntil, now), blocked: true };
  }

  const resetAt = new Date(after.windowStart.getTime() + windowMs);
  return { allowed: false, count, limit, retryAfterSeconds: secondsUntil(resetAt, now), blocked: false };
}

/** Read-only check: would the next hit be allowed? Does not count a hit. */
export async function peekRateLimit(params: {
  scope: string;
  subject: string;
  limit: number;
  windowMs: number;
}): Promise<RateLimitResult> {
  const { scope, subject, limit, windowMs } = params;
  const now = new Date();
  const row = await getRateLimitRow(rateLimitKey(scope, subject));

  if (!row) return { allowed: true, count: 0, limit, retryAfterSeconds: 0, blocked: false };
  if (row.blockedUntil && row.blockedUntil > now) {
    return { allowed: false, count: row.count, limit, retryAfterSeconds: secondsUntil(row.blockedUntil, now), blocked: true };
  }
  if (now.getTime() - row.windowStart.getTime() >= windowMs) {
    return { allowed: true, count: 0, limit, retryAfterSeconds: 0, blocked: false };
  }
  if (row.count < limit) return { allowed: true, count: row.count, limit, retryAfterSeconds: 0, blocked: false };
  const resetAt = new Date(row.windowStart.getTime() + windowMs);
  return { allowed: false, count: row.count, limit, retryAfterSeconds: secondsUntil(resetAt, now), blocked: false };
}

/** Forget a subject's counter (e.g. failed-login count after a successful login). */
export async function clearRateLimit(scope: string, subject: string): Promise<void> {
  await db().delete(abuseRateLimit).where(eq(abuseRateLimit.key, rateLimitKey(scope, subject)));
}

/** Housekeeping: drop counters untouched for `olderThanMs` that are not blocking anyone. */
export async function pruneRateLimits(olderThanMs: number): Promise<void> {
  const now = new Date();
  const cutoff = new Date(now.getTime() - olderThanMs);
  await db()
    .delete(abuseRateLimit)
    .where(
      and(
        sql`${abuseRateLimit.updatedAt} < ${cutoff}`,
        or(isNull(abuseRateLimit.blockedUntil), sql`${abuseRateLimit.blockedUntil} < ${now}`)
      )
    );
}

// ─── Grant decision (pure) ───────────────────────────────────────────────────
// The dedup matrix from the plan:
//
//   fingerprint | ip   | verdict                    | amount
//   match       | match| same person                | min(minAmount, decayed)
//   match       | miss | switched network, suspect  | max(minAmount, decayed)
//   miss        | match| another device, same exit  | max(minAmount, decayed)
//   miss        | miss | new user                   | base (not decayed)
//
// decayed = max(0, base - n * decayStep): a flat subtraction per prior match
// (cheap, never negative). n = number of prior non-revoked grants that
// matched. After `maxRepeats`
// matches nothing more is granted (`max_repeats`), so the ledger can tell a
// capped grant apart from one that merely decayed to 0. A request with
// neither fingerprint nor ip is treated as a script (`no_signal`, 0) — a real
// browser always yields at least the UA-based fallback fingerprint. A subject
// (email / anon id) that already
// received this scene's grant gets nothing (`duplicate`), and a no-bonus
// country gets nothing (`blocked_region`).

export type GrantDecision =
  | 'new'
  | 'same_person'
  | 'fp_match'
  | 'ip_match'
  | 'max_repeats'
  | 'duplicate'
  | 'no_signal'
  | 'blocked_region';

export interface GrantDecisionInput {
  baseAmount: number;
  minAmount: number;
  /** Prior grants whose fingerprint AND ip both match. */
  samePersonMatches: number;
  /** Prior grants whose fingerprint matches (superset of samePersonMatches). */
  fingerprintMatches: number;
  /** Prior grants whose ip matches (superset of samePersonMatches). */
  ipMatches: number;
  subjectAlreadyGranted: boolean;
  /** Neither a fingerprint nor an ip was available — only a script gets here. */
  missingSignals: boolean;
  blockedRegion: boolean;
  /** Matched grants beyond this count receive 0. Undefined = unlimited. */
  maxRepeats?: number;
  /** Credits subtracted per prior matched grant (default 1). */
  decayStep?: number;
}

export function decideGrant(input: GrantDecisionInput): { decision: GrantDecision; amount: number } {
  const base = Math.max(0, Math.floor(input.baseAmount));
  const min = Math.max(0, Math.floor(input.minAmount));

  if (input.subjectAlreadyGranted) return { decision: 'duplicate', amount: 0 };
  if (input.missingSignals) return { decision: 'no_signal', amount: 0 };
  if (input.blockedRegion) return { decision: 'blocked_region', amount: 0 };
  if (input.fingerprintMatches === 0 && input.ipMatches === 0) return { decision: 'new', amount: base };

  let decision: GrantDecision;
  let n: number;
  if (input.samePersonMatches > 0) {
    decision = 'same_person';
    n = input.samePersonMatches;
  } else if (input.fingerprintMatches > 0) {
    decision = 'fp_match';
    n = input.fingerprintMatches;
  } else {
    decision = 'ip_match';
    n = input.ipMatches;
  }

  if (input.maxRepeats !== undefined && n >= input.maxRepeats) return { decision: 'max_repeats', amount: 0 };

  const step = Math.max(0, Math.floor(input.decayStep ?? 1));
  const decayed = Math.max(0, base - n * step);
  const amount = decision === 'same_person' ? Math.min(min, decayed) : Math.max(min, decayed);
  return { decision, amount: Math.min(base, amount) };
}

// ─── Grant evaluation / ledger ───────────────────────────────────────────────

export type GrantSubjectType = 'email' | 'uuid';

export interface GrantContext {
  /** Entry point: 'signup' | 'guest' | 'checkin' | ... */
  scene: string;
  subjectType: GrantSubjectType;
  /** Normalized email (lib/email-policy normalizeEmail) or anon_id. */
  subject: string;
  userId?: string | null;
  fingerprint?: string | null;
  ip?: string | null;
  country?: string | null;
}

export interface GrantEvaluation {
  decision: GrantDecision;
  amount: number;
  baseAmount: number;
  priors: {
    subject: number;
    samePerson: number;
    fingerprint: number;
    ip: number;
  };
}

/**
 * Decide how much to grant without writing anything. Prior grants are looked
 * up in `priorScenes` (default: the same scene) — pass e.g. ['guest','signup']
 * so a visitor who already took guest credits is recognised at sign-up.
 */
export async function evaluateGrant(
  ctx: GrantContext,
  opts: {
    baseAmount: number;
    minAmount: number;
    maxRepeats?: number;
    decayStep?: number;
    noBonusCountries?: readonly string[];
    priorScenes?: string[];
  }
): Promise<GrantEvaluation> {
  const scenes = opts.priorScenes?.length ? opts.priorScenes : [ctx.scene];
  const fp = ctx.fingerprint || null;
  const ip = ctx.ip || null;

  const matchers = [
    and(eq(grantRecord.subjectType, ctx.subjectType), eq(grantRecord.subject, ctx.subject)),
    fp ? eq(grantRecord.fingerprint, fp) : undefined,
    ip ? eq(grantRecord.ip, ip) : undefined,
  ].filter((c) => c !== undefined);

  const priors = await db()
    .select({
      scene: grantRecord.scene,
      subjectType: grantRecord.subjectType,
      subject: grantRecord.subject,
      fingerprint: grantRecord.fingerprint,
      ip: grantRecord.ip,
    })
    .from(grantRecord)
    .where(
      and(
        inArray(grantRecord.scene, scenes),
        isNull(grantRecord.revokedAt),
        gt(grantRecord.amount, 0),
        matchers.length > 1 ? or(...matchers) : matchers[0]
      )
    );

  let subjectCount = 0;
  let fpCount = 0;
  let ipCount = 0;
  let bothCount = 0;
  for (const p of priors) {
    const sameSubject =
      p.scene === ctx.scene && p.subjectType === ctx.subjectType && p.subject === ctx.subject;
    if (sameSubject) subjectCount++;
    const fpHit = Boolean(fp && p.fingerprint === fp);
    const ipHit = Boolean(ip && p.ip === ip);
    if (fpHit) fpCount++;
    if (ipHit) ipCount++;
    if (fpHit && ipHit) bothCount++;
  }

  const { decision, amount } = decideGrant({
    baseAmount: opts.baseAmount,
    minAmount: opts.minAmount,
    samePersonMatches: bothCount,
    fingerprintMatches: fpCount,
    ipMatches: ipCount,
    subjectAlreadyGranted: subjectCount > 0,
    missingSignals: !fp && !ip,
    blockedRegion: isNoBonusCountry(ctx.country, opts.noBonusCountries),
    maxRepeats: opts.maxRepeats,
    decayStep: opts.decayStep,
  });

  return {
    decision,
    amount,
    baseAmount: Math.max(0, Math.floor(opts.baseAmount)),
    priors: { subject: subjectCount, samePerson: bothCount, fingerprint: fpCount, ip: ipCount },
  };
}

/** Append a decision to the ledger (also for refusals — they inform future n). */
export async function recordGrant(
  ctx: GrantContext,
  result: { decision: GrantDecision; baseAmount: number; amount: number; creditId?: string | null }
): Promise<GrantRecord> {
  const row = {
    id: getUuid(),
    scene: ctx.scene,
    subjectType: ctx.subjectType,
    subject: ctx.subject,
    userId: ctx.userId ?? null,
    fingerprint: ctx.fingerprint || null,
    ip: ctx.ip || null,
    country: ctx.country || null,
    decision: result.decision,
    baseAmount: result.baseAmount,
    amount: result.amount,
    creditId: result.creditId ?? null,
    createdAt: new Date(),
  };
  await db().insert(grantRecord).values(row);
  return { ...row, revokedAt: null, revokeReason: null };
}

/**
 * Evaluate + apply + record in one call.
 *
 * - `uuid` subjects: credits go to `guest_quota` unless `apply` is given.
 * - `email` subjects: pass `apply` to grant through the credits module and
 *   return the credit row id, e.g.
 *     apply: async (amount) => (await grant({ userId, credits: amount, ... })).id
 */
export async function grantAllowance(
  ctx: GrantContext,
  opts: Parameters<typeof evaluateGrant>[1] & {
    apply?: (amount: number) => Promise<string | undefined | void>;
    guestExpiresAt?: Date | null;
  }
): Promise<GrantEvaluation & { record: GrantRecord }> {
  const evaluation = await evaluateGrant(ctx, opts);

  let creditId: string | undefined | void;
  if (evaluation.amount > 0) {
    if (opts.apply) {
      creditId = await opts.apply(evaluation.amount);
    } else if (ctx.subjectType === 'uuid') {
      await addGuestCredits({
        anonId: ctx.subject,
        amount: evaluation.amount,
        fingerprint: ctx.fingerprint,
        ip: ctx.ip,
        country: ctx.country,
        expiresAt: opts.guestExpiresAt,
      });
    } else {
      throw new Error('grantAllowance: email subjects need an `apply` callback');
    }
  }

  const record = await recordGrant(ctx, {
    decision: evaluation.decision,
    baseAmount: evaluation.baseAmount,
    amount: evaluation.amount,
    creditId: creditId || null,
  });
  return { ...evaluation, record };
}

/**
 * Void ONE grant. `id` is the grant_record row id (a ledger number, not an
 * identity) — compare revokeGuestQuota, which takes an anon_id and cuts off
 * the whole account.
 *
 * Guest credits are taken back here; for registered users the returned
 * `creditId` tells the caller which credit row to void (this module never
 * touches the credits module).
 *
 * Example: ops finds anon-123 is a bot and calls revokeGrant('<row id>',
 * 'bot'). guest_quota.credits for anon-123 drops from 10 to 0, so any unused
 * balance is gone immediately, and the grant_record row is marked revoked so
 * it no longer counts as a prior grant.
 */
export async function revokeGrant(id: string, reason: string): Promise<GrantRecord | undefined> {
  const [row] = await db().select().from(grantRecord).where(eq(grantRecord.id, id)).limit(1);
  if (!row || row.revokedAt) return row;

  const now = new Date();
  await db()
    .update(grantRecord)
    .set({ revokedAt: now, revokeReason: reason })
    .where(and(eq(grantRecord.id, id), isNull(grantRecord.revokedAt)));

  if (row.subjectType === 'uuid' && row.amount > 0) {
    await db()
      .update(guestQuota)
      .set({ credits: sql`${guestQuota.credits} - ${row.amount}`, updatedAt: now })
      .where(eq(guestQuota.anonId, row.subject));
  }
  return { ...row, revokedAt: now, revokeReason: reason };
}

/** Grants to one subject since a point in time (daily / weekly caps). */
export async function getGrantTotals(params: {
  scene: string;
  subjectType: GrantSubjectType;
  subject: string;
  since?: Date;
}): Promise<{ count: number; amount: number }> {
  const conditions = [
    eq(grantRecord.scene, params.scene),
    eq(grantRecord.subjectType, params.subjectType),
    eq(grantRecord.subject, params.subject),
    isNull(grantRecord.revokedAt),
    gt(grantRecord.amount, 0),
    params.since ? gte(grantRecord.createdAt, params.since) : undefined,
  ].filter((c) => c !== undefined);
  return sumGrants(and(...conditions));
}

/**
 * Grants to any subject sharing the device fingerprint or ip since a point in
 * time — merges multiple accounts on one device/exit for check-in style caps.
 */
export async function getDeviceGrantTotals(params: {
  scene: string;
  fingerprint?: string | null;
  ip?: string | null;
  since?: Date;
}): Promise<{ count: number; amount: number }> {
  const matchers = [
    params.fingerprint ? eq(grantRecord.fingerprint, params.fingerprint) : undefined,
    params.ip ? eq(grantRecord.ip, params.ip) : undefined,
  ].filter((c) => c !== undefined);
  if (matchers.length === 0) return { count: 0, amount: 0 };

  const conditions = [
    eq(grantRecord.scene, params.scene),
    isNull(grantRecord.revokedAt),
    gt(grantRecord.amount, 0),
    params.since ? gte(grantRecord.createdAt, params.since) : undefined,
    matchers.length > 1 ? or(...matchers) : matchers[0],
  ].filter((c) => c !== undefined);
  return sumGrants(and(...conditions));
}

async function sumGrants(where: ReturnType<typeof and>) {
  const [row] = await db()
    .select({
      count: sql<number>`count(*)`,
      amount: sql<number>`coalesce(sum(${grantRecord.amount}), 0)`,
    })
    .from(grantRecord)
    .where(where);
  return { count: Number(row?.count ?? 0), amount: Number(row?.amount ?? 0) };
}

// ─── Guest quota (anonymous visitors) ────────────────────────────────────────

export interface GuestBalance {
  credits: number;
  used: number;
  remaining: number;
  /** False when revoked or expired. */
  active: boolean;
  row: GuestQuota | undefined;
}

function toGuestBalance(row: GuestQuota | undefined, now = new Date()): GuestBalance {
  if (!row) return { credits: 0, used: 0, remaining: 0, active: false, row };
  const active = !row.revokedAt && (!row.expiresAt || row.expiresAt > now);
  const remaining = active ? Math.max(0, row.credits - row.used) : 0;
  return { credits: row.credits, used: row.used, remaining, active, row };
}

export async function getGuestQuota(anonId: string): Promise<GuestBalance> {
  const [row] = await db().select().from(guestQuota).where(eq(guestQuota.anonId, anonId)).limit(1);
  return toGuestBalance(row);
}

/** Add credits to a visitor (upsert). Also refreshes the last-seen signals. */
export async function addGuestCredits(params: {
  anonId: string;
  amount: number;
  fingerprint?: string | null;
  ip?: string | null;
  country?: string | null;
  expiresAt?: Date | null;
}): Promise<GuestBalance> {
  const now = new Date();
  const signals = {
    fingerprint: params.fingerprint || null,
    ip: params.ip || null,
    country: params.country || null,
  };
  const existing = await getGuestQuota(params.anonId);

  if (!existing.row) {
    try {
      await db().insert(guestQuota).values({
        anonId: params.anonId,
        credits: params.amount,
        used: 0,
        expiresAt: params.expiresAt ?? null,
        createdAt: now,
        updatedAt: now,
        ...signals,
      });
      return getGuestQuota(params.anonId);
    } catch {
      // Insert race — fall through to the increment.
    }
  }

  await db()
    .update(guestQuota)
    .set({
      credits: sql`${guestQuota.credits} + ${params.amount}`,
      updatedAt: now,
      ...(params.expiresAt !== undefined ? { expiresAt: params.expiresAt } : {}),
      ...signals,
    })
    .where(eq(guestQuota.anonId, params.anonId));
  return getGuestQuota(params.anonId);
}

/**
 * Spend visitor credits. Atomic without transactions (D1 has none): the
 * conditional update is guarded by the `used` value we read, and the nonce
 * written into `last_op_id` tells us whether our update was the one applied.
 */
export async function consumeGuestCredits(params: {
  anonId: string;
  amount: number;
}): Promise<{ success: boolean; remaining: number }> {
  const amount = Math.max(0, Math.floor(params.amount));
  let balance = await getGuestQuota(params.anonId);

  for (let attempt = 0; attempt < 3; attempt++) {
    if (!balance.row || !balance.active || balance.remaining < amount) {
      return { success: false, remaining: balance.remaining };
    }
    if (amount === 0) return { success: true, remaining: balance.remaining };

    const opId = getUuid();
    await db()
      .update(guestQuota)
      .set({ used: sql`${guestQuota.used} + ${amount}`, lastOpId: opId, updatedAt: new Date() })
      .where(
        and(
          eq(guestQuota.anonId, params.anonId),
          eq(guestQuota.used, balance.row.used),
          isNull(guestQuota.revokedAt)
        )
      );

    balance = await getGuestQuota(params.anonId);
    if (balance.row?.lastOpId === opId) {
      return { success: true, remaining: balance.remaining };
    }
    // Someone else moved `used` first — re-check with the fresh row.
  }
  return { success: false, remaining: balance.remaining };
}

/** Give back credits (e.g. the job failed before producing output). */
export async function refundGuestCredits(anonId: string, amount: number): Promise<GuestBalance> {
  const n = Math.max(0, Math.floor(amount));
  if (n > 0) {
    await db()
      .update(guestQuota)
      .set({
        used: sql`case when ${guestQuota.used} > ${n} then ${guestQuota.used} - ${n} else 0 end`,
        updatedAt: new Date(),
      })
      .where(eq(guestQuota.anonId, anonId));
  }
  return getGuestQuota(anonId);
}

/**
 * Cut a visitor off entirely; their balance reads as 0 from now on, and any
 * later addGuestCredits still reads as 0 (the account stays revoked).
 *
 * The key is the anon_id (the WHOLE account) — compare revokeGrant, which
 * takes a grant_record id and voids ONE grant. grant_record rows are left
 * untouched here.
 */
export async function revokeGuestQuota(anonId: string): Promise<void> {
  await db()
    .update(guestQuota)
    .set({ revokedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(guestQuota.anonId, anonId), isNull(guestQuota.revokedAt)));
}

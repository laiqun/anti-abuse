// Excerpt: anti-abuse tables from src/config/db/schema.sqlite.ts.
// Relies on the template's own imports and the existing user table.
// ─── Anti-abuse ──────────────────────────────────────────────────────────────
// Backing tables for src/modules/anti-abuse/service.ts: persistent rate-limit
// counters, a ledger of every free-credit grant decision (dedup by email /
// anon id / fingerprint / ip), and a credit balance for anonymous visitors
// (registered users keep using the `credit` table).

export const abuseRateLimit = table(
  'abuse_rate_limit',
  {
    // `${scope}|${subject}` — e.g. "signup_ip|1.2.3.4", "otp_email|a@b.com"
    key: text('key').primaryKey(),
    scope: text('scope').notNull(),
    subject: text('subject').notNull(),
    count: integer('count').notNull().default(0),
    windowStart: integer('window_start', { mode: 'timestamp_ms' }).notNull(),
    // Hard block (login brute-force etc.); null = not blocked.
    blockedUntil: integer('blocked_until', { mode: 'timestamp_ms' }),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' })
      .notNull()
      .$defaultFn(() => new Date()),
  },
  (t) => [index('idx_abuse_rate_limit_scope_updated').on(t.scope, t.updatedAt)]
);

export const grantRecord = table(
  'grant_record',
  {
    id: text('id').primaryKey(),
    // Which free-credit entrypoint: signup | guest | checkin | ...
    scene: text('scene').notNull(),
    // email (normalized, registered users) | uuid (anon_id cookie, visitors)
    subjectType: text('subject_type').notNull(),
    subject: text('subject').notNull(),
    userId: text('user_id').references(() => user.id),
    // sha256 of the device fingerprint; see src/lib/request-identity.ts
    fingerprint: text('fingerprint'),
    ip: text('ip'),
    country: text('country'),
    // Dedup matrix outcome: new | same_person | fp_match | ip_match | max_repeats |
    // duplicate | no_signal | blocked_region
    decision: text('decision').notNull(),
    baseAmount: integer('base_amount').notNull(),
    // Credits actually granted after the decay rule (0 = refused).
    amount: integer('amount').notNull(),
    // Reference to the applied grant: credit.id for registered users.
    creditId: text('credit_id'),
    revokedAt: integer('revoked_at', { mode: 'timestamp' }),
    revokeReason: text('revoke_reason'),
    createdAt: integer('created_at', { mode: 'timestamp' })
      .notNull()
      .$defaultFn(() => new Date()),
  },
  (t) => [
    index('idx_grant_record_subject').on(t.scene, t.subjectType, t.subject),
    index('idx_grant_record_fingerprint').on(t.scene, t.fingerprint),
    index('idx_grant_record_ip').on(t.scene, t.ip),
    index('idx_grant_record_user').on(t.userId),
  ]
);

export const guestQuota = table(
  'guest_quota',
  {
    anonId: text('anon_id').primaryKey(),
    // Total credits ever granted (minus revocations).
    credits: integer('credits').notNull().default(0),
    used: integer('used').notNull().default(0),
    // Nonce of the last successful consume — lets consumeGuestCredits detect
    // whether its conditional update won without dialect-specific rowcounts.
    lastOpId: text('last_op_id'),
    fingerprint: text('fingerprint'),
    ip: text('ip'),
    country: text('country'),
    expiresAt: integer('expires_at', { mode: 'timestamp' }),
    revokedAt: integer('revoked_at', { mode: 'timestamp' }),
    createdAt: integer('created_at', { mode: 'timestamp' })
      .notNull()
      .$defaultFn(() => new Date()),
    updatedAt: integer('updated_at', { mode: 'timestamp' })
      .notNull()
      .$defaultFn(() => new Date()),
  },
  (t) => [index('idx_guest_quota_fingerprint').on(t.fingerprint)]
);

export type AbuseRateLimit = typeof abuseRateLimit.$inferSelect;
export type GrantRecord = typeof grantRecord.$inferSelect;
export type NewGrantRecord = typeof grantRecord.$inferInsert;
export type GuestQuota = typeof guestQuota.$inferSelect;

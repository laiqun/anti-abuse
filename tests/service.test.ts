// Tests for src/modules/anti-abuse/service.ts (pure logic only — no DB).
// Run: pnpm test

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { decideGrant, getAntiAbuseSettings } from '@/modules/anti-abuse/service';

describe('decideGrant', () => {
  const base = {
    baseAmount: 10,
    minAmount: 2,
    subjectAlreadyGranted: false,
    missingSignals: false,
    blockedRegion: false,
  };

  it('grants the full amount to a brand-new device + ip', () => {
    const r = decideGrant({ ...base, samePersonMatches: 0, fingerprintMatches: 0, ipMatches: 0 });
    assert.deepEqual(r, { decision: 'new', amount: 10 });
  });

  it('treats a request with neither fingerprint nor ip as a script', () => {
    const r = decideGrant({ ...base, missingSignals: true, samePersonMatches: 0, fingerprintMatches: 0, ipMatches: 0 });
    assert.deepEqual(r, { decision: 'no_signal', amount: 0 });
  });

  it('refuses a subject that already took this grant', () => {
    const r = decideGrant({ ...base, subjectAlreadyGranted: true, samePersonMatches: 0, fingerprintMatches: 0, ipMatches: 0 });
    assert.deepEqual(r, { decision: 'duplicate', amount: 0 });
  });

  it('refuses no-bonus regions even when otherwise new', () => {
    const r = decideGrant({ ...base, blockedRegion: true, samePersonMatches: 0, fingerprintMatches: 0, ipMatches: 0 });
    assert.deepEqual(r, { decision: 'blocked_region', amount: 0 });
  });

  it('same person: minimum amount, then decays below it', () => {
    assert.deepEqual(
      decideGrant({ ...base, samePersonMatches: 1, fingerprintMatches: 1, ipMatches: 1 }),
      { decision: 'same_person', amount: 2 } // min(2, 10 - 1)
    );
    assert.deepEqual(
      decideGrant({ ...base, samePersonMatches: 3, fingerprintMatches: 3, ipMatches: 3, maxRepeats: 10, decayStep: 3 }),
      { decision: 'same_person', amount: 1 } // min(2, 10 - 3*3)
    );
  });

  it('fingerprint match on a new ip subtracts decayStep per prior grant, floored at minimum', () => {
    assert.deepEqual(
      decideGrant({ ...base, samePersonMatches: 0, fingerprintMatches: 1, ipMatches: 0 }),
      { decision: 'fp_match', amount: 9 } // default step 1
    );
    assert.deepEqual(
      decideGrant({ ...base, samePersonMatches: 0, fingerprintMatches: 2, ipMatches: 0, decayStep: 3 }),
      { decision: 'fp_match', amount: 4 } // 10 - 2*3
    );
    assert.deepEqual(
      decideGrant({ ...base, samePersonMatches: 0, fingerprintMatches: 2, ipMatches: 0, decayStep: 5 }),
      { decision: 'fp_match', amount: 2 } // max(2, 0)
    );
  });

  it('ip match on a new device decays too', () => {
    assert.deepEqual(
      decideGrant({ ...base, samePersonMatches: 0, fingerprintMatches: 0, ipMatches: 1, decayStep: 4 }),
      { decision: 'ip_match', amount: 6 }
    );
  });

  it('decay never goes negative, even for same person with minimum 0', () => {
    const r = decideGrant({
      ...base, minAmount: 0, samePersonMatches: 5, fingerprintMatches: 5, ipMatches: 5, decayStep: 4, maxRepeats: 99,
    });
    assert.deepEqual(r, { decision: 'same_person', amount: 0 }); // 10 - 20 → clamped to 0
  });

  it('stops entirely after maxRepeats matched grants', () => {
    assert.deepEqual(
      decideGrant({ ...base, samePersonMatches: 0, fingerprintMatches: 0, ipMatches: 3, maxRepeats: 3 }),
      { decision: 'max_repeats', amount: 0 }
    );
  });

  it('never exceeds the base amount and never goes negative', () => {
    const r = decideGrant({ ...base, minAmount: 50, samePersonMatches: 0, fingerprintMatches: 1, ipMatches: 0 });
    assert.equal(r.amount, 10);
    const z = decideGrant({ ...base, baseAmount: 0, samePersonMatches: 0, fingerprintMatches: 0, ipMatches: 0 });
    assert.equal(z.amount, 0);
  });
});

describe('getAntiAbuseSettings', () => {
  it('falls back to defaults on missing or garbage values', () => {
    const s = getAntiAbuseSettings({ abuse_guest_credits: 'abc', abuse_min_credits: '-4' });
    assert.equal(s.guestCredits, 10);
    assert.equal(s.minCredits, 1);
    assert.equal(s.maxRepeatGrants, 3);
    assert.equal(s.decayStep, 1);
    assert.deepEqual(s.noBonusCountries, ['IN']);
    assert.deepEqual(s.allowedEmailDomains, []);
  });

  it('parses configured values', () => {
    const s = getAntiAbuseSettings({
      abuse_guest_credits: '5',
      abuse_no_bonus_countries: 'in, pk',
      abuse_allowed_email_domains: 'gmail.com,@Outlook.com',
    });
    assert.equal(s.guestCredits, 5);
    assert.deepEqual(s.noBonusCountries, ['IN', 'PK']);
    assert.deepEqual(s.allowedEmailDomains, ['gmail.com', 'outlook.com']);
  });
});

// Tests for src/lib/email-policy.ts. Run: pnpm test

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { checkEmailPolicy, normalizeEmail, parseDomainList } from '@/lib/email-policy';

describe('email policy', () => {
  it('normalizes gmail dots and plus tags into one dedup key', () => {
    assert.equal(normalizeEmail('John.Doe+promo@GMAIL.com'), 'johndoe@gmail.com');
    assert.equal(normalizeEmail('john.doe@googlemail.com'), 'johndoe@gmail.com');
    assert.equal(normalizeEmail('a.b+tag@outlook.com'), 'a.b@outlook.com');
    assert.equal(normalizeEmail('not-an-email'), 'not-an-email');
  });

  it('whitelists domains and rejects invalid addresses', () => {
    const allowed = parseDomainList('gmail.com, googlemail.com');
    assert.equal(checkEmailPolicy('x@gmail.com', { allowedDomains: allowed }).ok, true);
    assert.deepEqual(checkEmailPolicy('x@yahoo.com', { allowedDomains: allowed }), {
      ok: false,
      reason: 'domain_not_allowed',
      domain: 'yahoo.com',
    });
    assert.equal(checkEmailPolicy('x@yahoo.com').ok, true); // empty whitelist = any
    assert.equal(checkEmailPolicy('x@yahoo.com', { blockedDomains: ['yahoo.com'] }).reason, 'domain_blocked');
    assert.equal(checkEmailPolicy('nope').reason, 'invalid');
    assert.equal(checkEmailPolicy(`${'a'.repeat(250)}@gmail.com`).reason, 'invalid'); // > 254 chars
  });
});

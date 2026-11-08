// Tests for src/lib/turnstile.ts (siteverify is stubbed, no network). Run: pnpm test

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { getTurnstileToken, verifyTurnstileToken } from '@/lib/turnstile';

describe('turnstile', () => {
  const stub = (body: unknown): typeof fetch => async () => Response.json(body);

  it('reads the token from header or explicit value', () => {
    const r = new Request('https://app.test/x', { headers: { 'cf-turnstile-response': 'tok' } });
    assert.equal(getTurnstileToken(r), 'tok');
    assert.equal(getTurnstileToken(r, 'body-tok'), 'body-tok');
    assert.equal(getTurnstileToken(new Request('https://app.test/x')), undefined);
  });

  it('fails closed without secret / token / network', async () => {
    assert.equal((await verifyTurnstileToken({ secret: '', token: 't' })).errorCodes[0], 'missing-input-secret');
    assert.equal((await verifyTurnstileToken({ secret: 's', token: '' })).errorCodes[0], 'missing-input-response');
    const boom: typeof fetch = async () => { throw new Error('offline'); };
    const r = await verifyTurnstileToken({ secret: 's', token: 't', fetchImpl: boom });
    assert.deepEqual(r, { success: false, errorCodes: ['internal-error'] });
  });

  it('passes through siteverify results and enforces expected action', async () => {
    const ok = await verifyTurnstileToken({
      secret: 's', token: 't', expectedAction: 'signup',
      fetchImpl: stub({ success: true, action: 'signup', hostname: 'app.test', challenge_ts: 'now' }),
    });
    assert.equal(ok.success, true);
    assert.equal(ok.hostname, 'app.test');

    const wrongAction = await verifyTurnstileToken({
      secret: 's', token: 't', expectedAction: 'signup',
      fetchImpl: stub({ success: true, action: 'login' }),
    });
    assert.equal(wrongAction.success, false);
    assert.deepEqual(wrongAction.errorCodes, ['action-mismatch']);

    const rejected = await verifyTurnstileToken({
      secret: 's', token: 't', fetchImpl: stub({ success: false, 'error-codes': ['timeout-or-duplicate'] }),
    });
    assert.equal(rejected.success, false);
    assert.deepEqual(rejected.errorCodes, ['timeout-or-duplicate']);
  });
});

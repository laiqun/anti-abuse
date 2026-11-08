// Tests for src/lib/request-identity.ts. Run: pnpm test

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { getClientCountry, getClientIp, getRequestIdentity, isNoBonusCountry, parseCountryList } from '@/lib/request-identity';

describe('request identity', () => {
  const req = (headers: Record<string, string>) => new Request('https://app.test/x', { headers });

  it('prefers cf-connecting-ip, then the first x-forwarded-for hop', () => {
    assert.equal(getClientIp(req({ 'cf-connecting-ip': '1.1.1.1', 'x-forwarded-for': '2.2.2.2' })), '1.1.1.1');
    assert.equal(getClientIp(req({ 'x-forwarded-for': '2.2.2.2, 3.3.3.3' })), '2.2.2.2');
    assert.equal(getClientIp(req({})), '');
  });

  it('reads the country and treats XX / T1 as unknown', () => {
    assert.equal(getClientCountry(req({ 'cf-ipcountry': 'in' })), 'IN');
    assert.equal(getClientCountry(req({ 'cf-ipcountry': 'XX' })), null);
    assert.equal(getClientCountry(req({})), null);
    assert.equal(isNoBonusCountry('IN'), true);
    assert.equal(isNoBonusCountry('US'), false);
    assert.equal(isNoBonusCountry(null), false);
    assert.deepEqual(parseCountryList('us, invalid, De'), ['US', 'DE']);
  });

  it('hashes a client fingerprint, or falls back to UA-derived one', async () => {
    const a = await getRequestIdentity(req({ 'x-device-fingerprint': 'visitor-1' }));
    const b = await getRequestIdentity(req({ 'x-device-fingerprint': 'visitor-1' }));
    const c = await getRequestIdentity(req({ 'user-agent': 'UA/1' }));
    assert.equal(a.fingerprintSource, 'client');
    assert.equal(a.fingerprint, b.fingerprint);
    assert.equal(a.fingerprint.length, 64);
    assert.equal(c.fingerprintSource, 'fallback');
    assert.notEqual(a.fingerprint, c.fingerprint);
    // Oversized client values are ignored, not trusted.
    const d = await getRequestIdentity(req({ 'x-device-fingerprint': 'x'.repeat(200) }));
    assert.equal(d.fingerprintSource, 'fallback');
  });
});

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { makeScanId } from '../../../src/core/serialization/index.js';

const digest = `3fa9c0d1${'e'.repeat(56)}`;

describe('makeScanId', () => {
  it('formats UTC time with milliseconds and the first 8 digest hex characters', () => {
    const date = new Date(Date.UTC(2026, 9, 13, 14, 25, 1, 123));
    assert.equal(makeScanId(date, digest), '20261013T142501.123Z-3fa9c0d1');
  });

  it('pads single-digit fields and milliseconds', () => {
    const date = new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 6));
    assert.equal(makeScanId(date, digest), '20260102T030405.006Z-3fa9c0d1');
  });

  it('pads the year to four digits', () => {
    // Date.UTC maps years 0..99 to 1900..1999, so set the year explicitly.
    const date = new Date(0);
    date.setUTCFullYear(5, 0, 1);
    assert.equal(makeScanId(date, digest), '00050101T000000.000Z-3fa9c0d1');
  });

  it('uses the UTC clock, not local time', () => {
    const date = new Date('2026-10-13T23:59:59.999+02:00');
    assert.equal(makeScanId(date, digest), '20261013T215959.999Z-3fa9c0d1');
  });

  it('rejects an invalid date', () => {
    assert.throws(() => makeScanId(new Date('nope'), digest), RangeError);
  });

  it('rejects a digest with fewer than 8 lowercase hex digits', () => {
    const date = new Date(0);
    assert.throws(() => makeScanId(date, 'abc1234'), TypeError);
    assert.throws(() => makeScanId(date, 'zzzzzzzz'), TypeError);
    assert.throws(() => makeScanId(date, '3FA9C0D1'), TypeError);
  });
});

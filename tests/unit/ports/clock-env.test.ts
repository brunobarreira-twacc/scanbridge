import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ProcessEnv } from '../../../src/cli/ports/env.js';
import { SystemClock } from '../../../src/cli/ports/clock.js';

describe('SystemClock', () => {
  it('returns the current time', () => {
    const before = Date.now();
    const now = new SystemClock().now().getTime();
    assert.ok(now >= before && now <= Date.now());
  });

  it('sleeps for at least the requested time', async () => {
    const started = Date.now();
    await new SystemClock().sleep(20);
    assert.ok(Date.now() - started >= 15);
  });
});

describe('ProcessEnv', () => {
  it('reads a set variable and reports an unset one as undefined', () => {
    process.env.SCANBRIDGE_ENV_TEST = 'value';
    try {
      const env = new ProcessEnv();
      assert.equal(env.get('SCANBRIDGE_ENV_TEST'), 'value');
    } finally {
      delete process.env.SCANBRIDGE_ENV_TEST;
    }
    assert.equal(new ProcessEnv().get('SCANBRIDGE_ENV_TEST'), undefined);
  });
});

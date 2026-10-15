import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { FetchHttpClient } from '../../../src/adapters/io/http.js';
import type { HttpResult } from '../../../src/contracts/ports.js';
import { SensitiveString } from '../../../src/contracts/sensitive.js';

type Handler = (req: IncomingMessage, res: ServerResponse, socket: Socket) => void;

let server: Server;
let base: string;
let handler: Handler = (_req, res) => res.end();
const seen: IncomingMessage[] = [];

before(async () => {
  server = createServer((req, res) => {
    seen.push(req);
    handler(req, res, req.socket);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const client = new FetchHttpClient();
const request = (path: string, extra: Partial<Parameters<FetchHttpClient['request']>[0]> = {}) =>
  client.request({ url: `${base}${path}`, headers: {}, timeoutMs: 2_000, maxBytes: 10_000, ...extra });

describe('FetchHttpClient', () => {
  it('returns status and body of a normal response', async () => {
    handler = (_req, res) => res.end('ok');
    const r = await request('/normal');
    assert.equal(r.kind, 'response');
    if (r.kind !== 'response') return;
    assert.equal(r.status, 200);
    assert.equal(Buffer.from(r.body).toString(), 'ok');
    assert.equal(r.truncated, false);
  });

  it('sends GET and the plain headers', async () => {
    handler = (_req, res) => res.end('');
    seen.length = 0;
    await request('/headers', { headers: { 'x-plain': 'p' } });
    assert.equal(seen.at(-1)?.method, 'GET');
    assert.equal(seen.at(-1)?.headers['x-plain'], 'p');
  });

  it('does not follow a 302 redirect', async () => {
    handler = (req, res) => {
      if (req.url === '/redirect') {
        res.writeHead(302, { location: '/landing' });
        res.end();
        return;
      }
      res.end('landed');
    };
    seen.length = 0;
    const r = await request('/redirect');
    assert.equal(r.kind, 'response');
    if (r.kind !== 'response') return;
    assert.equal(r.status, 302);
    assert.equal(seen.filter((req) => req.url === '/landing').length, 0);
  });

  it('returns timeout for a slow response', async () => {
    handler = (_req, res) => setTimeout(() => res.end('late'), 1_000);
    const r = await request('/slow', { timeoutMs: 100 });
    assert.deepEqual(r, { kind: 'timeout' });
  });

  it('returns truncated for a body over the cap and keeps exactly maxBytes', async () => {
    handler = (_req, res) => res.end('x'.repeat(2_000));
    const r = await request('/big', { maxBytes: 1_000 });
    assert.equal(r.kind, 'response');
    if (r.kind !== 'response') return;
    assert.equal(r.body.byteLength, 1_000);
    assert.equal(r.truncated, true);
  });

  it('is not truncated when the body is one byte under maxBytes', async () => {
    handler = (_req, res) => res.end('x'.repeat(999));
    const r = await request('/under', { maxBytes: 1_000 });
    assert.equal(r.kind, 'response');
    if (r.kind !== 'response') return;
    assert.equal(r.body.byteLength, 999);
    assert.equal(r.truncated, false);
  });

  it('is not truncated when the body is exactly maxBytes', async () => {
    handler = (_req, res) => res.end('x'.repeat(1_000));
    const r = await request('/exact', { maxBytes: 1_000 });
    assert.equal(r.kind, 'response');
    if (r.kind !== 'response') return;
    assert.equal(r.body.byteLength, 1_000);
    assert.equal(r.truncated, false);
  });

  it('is truncated when the body is one byte over maxBytes', async () => {
    handler = (_req, res) => res.end('x'.repeat(1_001));
    const r = await request('/over-by-one', { maxBytes: 1_000 });
    assert.equal(r.kind, 'response');
    if (r.kind !== 'response') return;
    assert.equal(r.body.byteLength, 1_000);
    assert.equal(r.truncated, true);
  });

  it('returns closed when the connection is destroyed before a response', async () => {
    handler = (_req, _res, socket) => socket.destroy();
    const r = await request('/destroyed');
    assert.deepEqual(r, { kind: 'closed' });
  });

  it('returns an error code for a refused connection, never a message', async () => {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const r = await client.request({ url: `http://127.0.0.1:${port}/`, headers: {}, timeoutMs: 2_000, maxBytes: 10 });
    assert.deepEqual(r, { kind: 'error', code: 'ECONNREFUSED' });
  });

  it('delivers a sensitive header to the server and never returns its value', async () => {
    const canary = 'canary-zap-key-7f3a9c';
    handler = (_req, res) => res.end('ok');
    seen.length = 0;
    const r = await request('/secret', {
      headers: { accept: 'application/json' },
      sensitiveHeaders: { 'x-zap-api-key': new SensitiveString(canary) },
    });
    assert.equal(seen.at(-1)?.headers['x-zap-api-key'], canary);
    assert.equal(JSON.stringify(r).includes(canary), false);
    assert.equal(String(r).includes(canary), false);
  });

  it('keeps the sensitive header out of errors and timeouts', async () => {
    const canary = 'canary-zap-key-timeout-91b2';
    handler = (_req, res) => setTimeout(() => res.end('late'), 1_000);
    const timedOut = await request('/secret-slow', {
      timeoutMs: 100,
      sensitiveHeaders: { 'x-zap-api-key': new SensitiveString(canary) },
    });
    assert.deepEqual(timedOut, { kind: 'timeout' });

    handler = (_req, _res, socket) => socket.destroy();
    const closed: HttpResult = await request('/secret-closed', {
      sensitiveHeaders: { 'x-zap-api-key': new SensitiveString(canary) },
    });
    assert.deepEqual(closed, { kind: 'closed' });
    assert.equal(JSON.stringify([timedOut, closed]).includes(canary), false);
  });
});

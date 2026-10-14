import assert from 'node:assert/strict';
import { test } from 'node:test';
import { normalizeOrigin, normalizeUrl, UrlError } from '../../../src/core/fingerprints/url.js';

type Row = [input: string, origin: string, path: string, queryNames: string[], targetPath: string];

const TABLE: Row[] = [
  // scheme, host and default ports
  ['HTTP://Example.COM:80/a', 'http://example.com', '/a', [], '/a'],
  ['https://EXAMPLE.com:443/a', 'https://example.com', '/a', [], '/a'],
  ['https://example.com:8443/x', 'https://example.com:8443', '/x', [], '/x'],
  ['http://[::1]:8080/x', 'http://[::1]:8080', '/x', [], '/x'],
  // dot segments
  ['http://example.com/a/./b/../c', 'http://example.com', '/a/c', [], '/a/c'],
  ['http://example.com/a/b/../../../../c', 'http://example.com', '/c', [], '/c'],
  // percent decoding: unreserved only, remaining hex uppercased
  ['http://example.com/%7Euser/%41%2fb', 'http://example.com', '/~user/A%2Fb', [], '/~user/A%2Fb'],
  ['http://example.com/a%2fb', 'http://example.com', '/a%2Fb', [], '/a%2Fb'],
  ['http://example.com/a%c3%a9', 'http://example.com', '/a%C3%A9', [], '/a%C3%A9'],
  ['http://example.com/a%2dz%2ez%5fz%7ez', 'http://example.com', '/a-z.z_z~z', [], '/a-z.z_z~z'],
  ['http://example.com/a b', 'http://example.com', '/a%20b', [], '/a%20b'],
  // trailing slash
  ['http://example.com/a/', 'http://example.com', '/a/', [], '/a/'],
  ['http://example.com/a', 'http://example.com', '/a', [], '/a'],
  ['http://example.com', 'http://example.com', '/', [], '/'],
  // query: values removed, names sorted and deduplicated
  [
    'http://example.com/s?z=1&a=2&a=3&m',
    'http://example.com',
    '/s',
    ['a', 'm', 'z'],
    '/s?a&m&z',
  ],
  ['http://example.com/s?x=%41', 'http://example.com', '/s', ['x'], '/s?x'],
  ['http://example.com/s?a%41=1', 'http://example.com', '/s', ['aA'], '/s?aA'],
  ['http://example.com/s?=v&&', 'http://example.com', '/s', [], '/s'],
  ['http://example.com/s?', 'http://example.com', '/s', [], '/s'],
];

for (const [input, origin, path, queryNames, targetPath] of TABLE) {
  test(`normalizeUrl(${JSON.stringify(input)})`, () => {
    const result = normalizeUrl(input);
    assert.deepEqual(result, {
      origin,
      path,
      queryNames,
      url: `${origin}${targetPath}`,
      targetPath,
    });
  });
}

test('query values never appear in the normalized URL', () => {
  const result = normalizeUrl('https://example.com/p?token=secret&q=attack');
  assert.equal(result.url, 'https://example.com/p?q&token');
  assert.ok(!result.url.includes('secret'));
  assert.ok(!result.targetPath.includes('attack'));
});

const REJECTED: string[] = [
  '',
  '/relative/path',
  'ftp://example.com/',
  'javascript:alert(1)',
  'http:///no-host',
  'http://user:pass@example.com/',
  'http://user@example.com/',
  'http://@example.com/',
  'http://example.com/#fragment',
  'http://example.com/#',
  'http://example.com/a\tb',
  'http://example.com/a\nb',
  'http://example.com/\u007f',
  ' http://example.com/',
  'http://example.com/ ',
  'http://exa mple.com/',
  'http://example.com\\a',
  'http://example.com/%zz',
  'http://example.com/%',
  'http://example.com/s?a%G1=1',
];

for (const input of REJECTED) {
  test(`normalizeUrl rejects ${JSON.stringify(input)}`, () => {
    assert.throws(() => normalizeUrl(input), UrlError);
  });
}

const ORIGINS: [input: string, origin: string][] = [
  ['HTTPS://Example.com:443', 'https://example.com'],
  ['http://example.com:8080', 'http://example.com:8080'],
  ['http://example.com:80', 'http://example.com'],
];

for (const [input, origin] of ORIGINS) {
  test(`normalizeOrigin(${JSON.stringify(input)}) = ${origin}`, () => {
    assert.equal(normalizeOrigin(input), origin);
  });
}

const BAD_ORIGINS: string[] = [
  'http://example.com/',
  'http://example.com/a',
  'http://example.com?x=1',
  'http://example.com#f',
  'http://user@example.com',
  'http://user:pw@example.com',
  'ftp://example.com',
  'example.com',
  'http://',
];

for (const input of BAD_ORIGINS) {
  test(`normalizeOrigin rejects ${JSON.stringify(input)}`, () => {
    assert.throws(() => normalizeOrigin(input), UrlError);
  });
}

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { sha256Utf8 } from '../../../src/core/serialization/index.js';
import {
  ArtifactExistsError,
  EmptyArtifactError,
  ReportStore,
  ScanDirectoryExistsError,
} from '../../../src/cli/store/report-store.js';

const SCAN_ID = '20261013T142501.123Z-3fa9c0d1';
const freshBase = () => join(realpathSync(mkdtempSync(join(tmpdir(), 'store-'))), 'out');

describe('ReportStore.createScanDirectory', () => {
  it('creates a missing base and the scan directory under its real path', async () => {
    const base = freshBase();
    const store = await ReportStore.createScanDirectory(base, SCAN_ID);
    assert.equal(store.directory, join(realpathSync(base), SCAN_ID));
    assert.ok(statSync(store.directory).isDirectory());
  });

  it('fails on an existing scan directory and leaves its files untouched', async () => {
    const base = freshBase();
    const store = await ReportStore.createScanDirectory(base, SCAN_ID);
    await store.writeNormalized('{"kept":true}\n');

    await assert.rejects(ReportStore.createScanDirectory(base, SCAN_ID), ScanDirectoryExistsError);
    assert.equal(readFileSync(join(store.directory, 'normalized.json'), 'utf8'), '{"kept":true}\n');
  });

  it('writes through a symlinked base into the real directory', async () => {
    const real = freshBase();
    mkdirSync(real, { recursive: true });
    const link = join(realpathSync(mkdtempSync(join(tmpdir(), 'link-'))), 'out-link');
    symlinkSync(real, link);

    const store = await ReportStore.createScanDirectory(link, SCAN_ID);
    assert.equal(store.directory, join(realpathSync(real), SCAN_ID));
  });

  it('rejects a scan id that could escape the base', async () => {
    const base = freshBase();
    for (const bad of ['../escape', 'a/b', '20261013T142501.123Z-3fa9c0d', SCAN_ID.toUpperCase()]) {
      await assert.rejects(ReportStore.createScanDirectory(base, bad), TypeError, bad);
    }
  });
});

describe('ReportStore writes', () => {
  it('writes normalized and scan-result files and reports their bytes', async () => {
    const store = await ReportStore.createScanDirectory(freshBase(), SCAN_ID);
    const normalized = '{\n  "findings": []\n}\n';
    const written = await store.writeNormalized(normalized);

    assert.deepEqual(written, {
      relativePath: 'normalized.json',
      bytes: Buffer.byteLength(normalized, 'utf8'),
      sha256: sha256Utf8(normalized),
    });
    await store.writeScanResult('{"status":"complete"}\n');
    assert.equal(readFileSync(join(store.directory, 'scan-result.json'), 'utf8'), '{"status":"complete"}\n');
  });

  it('hash of a raw file equals SHA-256 of the exact bytes read back from disk', async () => {
    const store = await ReportStore.createScanDirectory(freshBase(), SCAN_ID);
    const raw = '{\n  "name": "é",\n  "list": [3, 1]\n}\n';
    const written = await store.writeRaw('semgrep.json', raw);

    assert.equal(written.relativePath, 'raw/semgrep.json');
    const onDisk = readFileSync(join(store.directory, 'raw', 'semgrep.json'));
    assert.equal(written.sha256, sha256Utf8(raw));
    assert.equal(written.sha256, createHash('sha256').update(onDisk).digest('hex'));
    assert.equal(written.bytes, onDisk.length);
  });

  it('never overwrites an existing artifact', async () => {
    const store = await ReportStore.createScanDirectory(freshBase(), SCAN_ID);
    await store.writeNormalized('first\n');
    await assert.rejects(store.writeNormalized('second\n'), ArtifactExistsError);
    assert.equal(readFileSync(join(store.directory, 'normalized.json'), 'utf8'), 'first\n');

    await store.writeRaw('semgrep.json', 'one\n');
    await assert.rejects(store.writeRaw('semgrep.json', 'two\n'), ArtifactExistsError);
    assert.equal(readFileSync(join(store.directory, 'raw', 'semgrep.json'), 'utf8'), 'one\n');
  });

  it('refuses empty content and creates nothing for it', async () => {
    const store = await ReportStore.createScanDirectory(freshBase(), SCAN_ID);
    await assert.rejects(store.writeNormalized(''), EmptyArtifactError);
    await assert.rejects(store.writeScanResult(''), EmptyArtifactError);
    await assert.rejects(store.writeRaw('semgrep.json', ''), EmptyArtifactError);

    assert.deepEqual(readdirSync(store.directory), []);
  });

  it('rejects raw names that are not plain json file names', async () => {
    const store = await ReportStore.createScanDirectory(freshBase(), SCAN_ID);
    for (const bad of ['../x.json', 'raw/x.json', 'x.txt', '.hidden.json', '']) {
      await assert.rejects(store.writeRaw(bad, '{}\n'), TypeError, bad);
    }
    assert.deepEqual(readdirSync(store.directory), []);
  });

  it('leaves a file that exists before a refused write untouched', async () => {
    const base = freshBase();
    const store = await ReportStore.createScanDirectory(base, SCAN_ID);
    writeFileSync(join(store.directory, 'scan-result.json'), 'earlier\n');
    await assert.rejects(store.writeScanResult(''), EmptyArtifactError);
    assert.equal(readFileSync(join(store.directory, 'scan-result.json'), 'utf8'), 'earlier\n');
  });
});

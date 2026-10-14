import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';
import { renderSchemaFile, SCHEMA_DOCUMENTS } from '../../../src/schemas/index.js';

// Compiled to dist/tests/unit/schemas, so four levels up is the repository root.
const schemasDir = resolve(import.meta.dirname, '../../../../schemas');

describe('committed schemas match regenerated output', () => {
  for (const { name, schema } of SCHEMA_DOCUMENTS) {
    it(`schemas/${name}.schema.json`, async () => {
      const committed = await readFile(resolve(schemasDir, `${name}.schema.json`), 'utf8');
      assert.equal(committed, renderSchemaFile(schema), `run "npm run gen:schemas" and commit the result`);
    });
  }
});

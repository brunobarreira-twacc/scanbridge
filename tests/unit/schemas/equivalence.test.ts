import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { emitJsonSchema, SCHEMA_DOCUMENTS } from '../../../src/schemas/index.js';
import {
  type CorpusEntry,
  compareCorpus,
  doctorCorpus,
  errorEnvelopeCorpus,
  normalizedCorpus,
  scanResultCorpus,
} from './fixtures.js';

const corpora: Record<string, CorpusEntry[]> = {
  normalized: normalizedCorpus,
  'scan-result': scanResultCorpus,
  'error-envelope': errorEnvelopeCorpus,
  'doctor-result': doctorCorpus,
  'compare-result': compareCorpus,
};

const ajv = new Ajv2020({ strict: true });

describe('Zod and the emitted JSON Schema agree on every corpus document', () => {
  for (const { name, schema } of SCHEMA_DOCUMENTS) {
    it(name, () => {
      const corpus = corpora[name];
      assert.ok(corpus, `no corpus for ${name}`);
      assert.ok(corpus.filter((e) => e.valid).length >= 5, `${name} needs at least 5 valid documents`);
      assert.ok(corpus.filter((e) => !e.valid).length >= 8, `${name} needs at least 8 invalid documents`);

      const validate = ajv.compile(emitJsonSchema(schema));
      for (const entry of corpus) {
        const zodVerdict = schema.safeParse(entry.doc).success;
        const ajvVerdict = validate(entry.doc) === true;
        assert.equal(ajvVerdict, zodVerdict, `verdict differs (ajv vs zod): ${entry.label}`);
        assert.equal(zodVerdict, entry.valid, `unexpected verdict: ${entry.label}`);
      }
    });
  }
});

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { z } from 'zod';
import { emitJsonSchema, OBJECT_TYPES, SCHEMA_DOCUMENTS } from '../../../src/schemas/index.js';

describe('OBJECT_TYPES', () => {
  it('lists only Zod object schemas, each strict', () => {
    for (const [name, schema] of Object.entries(OBJECT_TYPES)) {
      assert.ok(schema instanceof z.ZodObject, `${name} is not a Zod object`);
      assert.equal(emitJsonSchema(schema).additionalProperties, false, `${name} accepts unknown keys`);
    }
  });

  it('covers the normalized document, the finding, and each envelope', () => {
    for (const name of ['NormalizedDocument', 'Finding', 'Occurrence', 'ScanResult', 'ErrorEnvelope', 'DoctorResult', 'CompareResult']) {
      assert.ok(name in OBJECT_TYPES, `missing ${name}`);
    }
  });
});

/** Every `number` node must pin a single value (`const`), so no fractional value can pass. */
const unpinnedNumbers = (node: unknown, path = '$'): string[] => {
  if (Array.isArray(node)) return node.flatMap((child, i) => unpinnedNumbers(child, `${path}[${i}]`));
  if (node === null || typeof node !== 'object') return [];
  const record = node as Record<string, unknown>;
  const here = record.type === 'number' && !('const' in record) ? [path] : [];
  return [...here, ...Object.entries(record).flatMap(([key, child]) => unpinnedNumbers(child, `${path}.${key}`))];
};

describe('emitted schemas use integers only', () => {
  for (const { name, schema } of SCHEMA_DOCUMENTS) {
    it(name, () => {
      assert.deepEqual(unpinnedNumbers(emitJsonSchema(schema)), []);
    });
  }
});

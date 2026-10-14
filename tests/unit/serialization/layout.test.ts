import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { OBJECT_TYPES } from '../../../src/schemas/index.js';
import { FIELD_ORDER, LAYOUT, type Rule } from '../../../src/core/serialization/layout.js';

describe('declared field-order lists', () => {
  it('exist for exactly the object types in OBJECT_TYPES', () => {
    assert.deepEqual(Object.keys(LAYOUT).sort(), Object.keys(OBJECT_TYPES).sort());
  });

  for (const [name, schema] of Object.entries(OBJECT_TYPES)) {
    it(`${name} covers exactly the Zod keys, once each`, () => {
      const declared = FIELD_ORDER[name] ?? [];
      assert.equal(new Set(declared).size, declared.length, `${name} repeats a key`);
      assert.deepEqual([...declared].sort(), Object.keys(schema.shape).sort());
    });
  }

  it('reference only object types that exist', () => {
    const referenced = (rule: Rule): string[] => {
      switch (rule.kind) {
        case 'object':
        case 'items':
          return [rule.type];
        case 'union':
          return Object.values(rule.members);
        default:
          return [];
      }
    };
    for (const [name, layout] of Object.entries(LAYOUT)) {
      for (const [field, rule] of Object.entries(layout)) {
        for (const target of referenced(rule)) {
          assert.ok(target in OBJECT_TYPES, `${name}.${field} references unknown type ${target}`);
        }
      }
    }
  });
});

import { z } from 'zod';

/** Emits the JSON Schema (draft 2020-12) for a Zod schema. Key order is Zod's, which is fixed by the code. */
export function emitJsonSchema(schema: z.ZodType): Record<string, unknown> {
  return z.toJSONSchema(schema, { target: 'draft-2020-12' }) as Record<string, unknown>;
}

/** The exact bytes of a committed schema file: 2-space indent, LF, one trailing newline. */
export function renderSchemaFile(schema: z.ZodType): string {
  return `${JSON.stringify(emitJsonSchema(schema), null, 2)}\n`;
}

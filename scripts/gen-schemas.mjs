// Writes schemas/<name>.schema.json from the compiled Zod schemas in dist/.
// `--check` regenerates in memory and exits 1 on any difference or missing file.
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCHEMA_DOCUMENTS, renderSchemaFile } from '../dist/src/schemas/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'schemas');
const check = process.argv.includes('--check');

const expected = new Map(
  SCHEMA_DOCUMENTS.map(({ name, schema }) => [`${name}.schema.json`, renderSchemaFile(schema)]),
);

if (check) {
  const problems = [];
  for (const [file, content] of expected) {
    let actual;
    try {
      actual = await readFile(join(outDir, file), 'utf8');
    } catch {
      problems.push(`missing: schemas/${file}`);
      continue;
    }
    if (actual !== content) problems.push(`differs: schemas/${file}`);
  }
  // A stale file with no source document is also drift.
  const present = (await readdir(outDir).catch(() => [])).filter((f) => f.endsWith('.schema.json'));
  for (const file of present) {
    if (!expected.has(file)) problems.push(`stale: schemas/${file}`);
  }
  if (problems.length > 0) {
    console.error(`Schema drift detected. Run "npm run gen:schemas" and commit the result.\n${problems.join('\n')}`);
    process.exit(1);
  }
  console.log(`Schemas are up to date (${expected.size} files).`);
} else {
  await mkdir(outDir, { recursive: true });
  for (const [file, content] of expected) {
    await writeFile(join(outDir, file), content);
  }
  console.log(`Wrote ${expected.size} schema files to schemas/.`);
}

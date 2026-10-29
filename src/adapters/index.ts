import type { ToolCatalog } from '../contracts/adapter.js';
import { semgrepAdapter } from './semgrep/index.js';
import { sonarqubeAdapter } from './sonarqube/index.js';
import { zapAdapter } from './zap/index.js';

/** Fixed map of the built-in adapters; there is no plugin mechanism. */
export const catalog: ToolCatalog = { semgrep: semgrepAdapter, zap: zapAdapter, sonarqube: sonarqubeAdapter };

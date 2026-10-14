import type { Adapter, SemgrepProbeContext, SemgrepScanContext } from '../../contracts/adapter.js';
import { normalize } from './normalize.js';
import { parse, sourceRefs } from './parse.js';
import { probe } from './probe.js';
import { scan } from './scan.js';

export const semgrepAdapter: Adapter<SemgrepProbeContext, SemgrepScanContext> = {
  name: 'semgrep',
  probe,
  scan,
  parse,
  sourceRefs,
  normalize,
};

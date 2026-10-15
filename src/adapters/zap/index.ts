import type { Adapter, ZapLiveScanContext, ZapProbeContext } from '../../contracts/adapter.js';
import { normalize } from './normalize.js';
import { parse, sourceRefs } from './parse.js';
import { zapProbe } from './probe.js';
import { zapScan } from './scan.js';

export const zapAdapter: Adapter<ZapProbeContext, ZapLiveScanContext> = {
  name: 'zap',
  probe: zapProbe,
  scan: zapScan,
  parse,
  sourceRefs,
  normalize,
};

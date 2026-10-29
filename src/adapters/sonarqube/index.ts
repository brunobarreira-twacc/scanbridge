import type { Adapter, SonarQubeProbeContext, SonarQubeScanContext } from '../../contracts/adapter.js';
import { normalize } from './normalize.js';
import { parse, sourceRefs } from './parse.js';
import { sonarQubeProbe } from './probe.js';
import { sonarQubeScan } from './scan.js';

export const sonarqubeAdapter: Adapter<SonarQubeProbeContext, SonarQubeScanContext> = {
  name: 'sonarqube',
  probe: sonarQubeProbe,
  scan: sonarQubeScan,
  parse,
  sourceRefs,
  normalize,
};

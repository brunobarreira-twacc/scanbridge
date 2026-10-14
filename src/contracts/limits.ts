// MVP limits, the only place numeric limits may be defined (specs 01 and 04).
// [verify] V9: all values are revisited with real fixtures.

const KIB = 1024;
const MIB = 1024 * KIB;

// Text, in code points
export const TEXT_FIELD_MAX = 4_000; // title, description, detail
export const SNIPPET_FIELD_MAX = 2_000; // snippet, evidence

// Identifiers, in code points
export const RULE_ID_MAX = 256;
export const PRODUCER_REFERENCE_MAX = 128;
export const PATH_MAX = 1_024;
export const URL_MAX = 2_048;
export const METHOD_MAX = 16;
export const PARAM_MAX = 256;
export const REFERENCE_MAX = 2_048;
export const REFERENCES_PER_FINDING_MAX = 20;

// Sizes, in bytes
export const SOURCE_READ_MAX_BYTES = 1 * MIB;
export const RAW_JSON_MAX_BYTES = 50 * MIB; // Semgrep stdout; ZAP bytes across all pages; offline file
export const NORMALIZED_JSON_MAX_BYTES = 25 * MIB;

// Counts
export const FINDINGS_MAX = 10_000;
export const OCCURRENCES_PER_FINDING_MAX = 100;
export const TARGET_DIGEST_WALK_MAX_FILES = 100_000;
export const ZAP_ALERTS_PAGE_SIZE = 500;

// Timeouts, in seconds
export const SEMGREP_RULE_TIMEOUT_MIN = 1;
export const SEMGREP_RULE_TIMEOUT_MAX = 60;
export const SEMGREP_RULE_TIMEOUT_DEFAULT = 5;
export const SEMGREP_PROCESS_TIMEOUT_MIN = 60;
export const SEMGREP_PROCESS_TIMEOUT_MAX = 3_600;
export const SEMGREP_PROCESS_TIMEOUT_DEFAULT = 600;
export const ZAP_DEADLINE_MIN = 1;
export const ZAP_DEADLINE_MAX = 3_600;
export const ZAP_SPIDER_TIMEOUT_DEFAULT = 300;
export const ZAP_PASSIVE_TIMEOUT_DEFAULT = 120;

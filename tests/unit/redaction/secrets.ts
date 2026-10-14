// Synthetic, test-only secrets. None is a working credential.

export const PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEsynthetic\n-----END RSA PRIVATE KEY-----';
export const BEARER = 'Bearer SyntheticBearer123';
export const GITHUB_TOKEN = `ghp_${'Q'.repeat(36)}`;
export const GITHUB_PAT = `github_pat_${'Z9'.repeat(12)}`;
export const GITLAB_PAT = `glpat-${'Y8'.repeat(10)}`;
export const AWS_KEY_ID = 'AKIAQWERTYUIOPASDFGH';
export const SLACK_TOKEN = 'xoxb-1234567890-synthetic';
export const GOOGLE_KEY = `AIza${'S'.repeat(35)}`;
export const STRIPE_KEY = `sk_test_${'4'.repeat(24)}`;
export const NPM_TOKEN = `npm_${'N'.repeat(36)}`;
export const ASSIGNMENT_VALUE = 'SyntheticValue99';
export const ENV_SECRET = 'env-secret-value-1234';

/** One positive case per value rule 1–11, with the rule id that must replace it. */
export const VALUE_CASES: ReadonlyArray<{ id: string; input: string; secret: string }> = [
  { id: 'private-key', input: `key:\n${PRIVATE_KEY}\nend`, secret: 'MIIEFAKEsynthetic' },
  { id: 'bearer', input: `auth ${BEARER}`, secret: 'SyntheticBearer123' },
  { id: 'provider-github-token', input: `t=${GITHUB_TOKEN}`, secret: GITHUB_TOKEN },
  { id: 'provider-github-pat', input: GITHUB_PAT, secret: GITHUB_PAT },
  { id: 'provider-gitlab-pat', input: GITLAB_PAT, secret: GITLAB_PAT },
  { id: 'provider-aws-access-key-id', input: AWS_KEY_ID, secret: AWS_KEY_ID },
  { id: 'provider-slack-token', input: SLACK_TOKEN, secret: SLACK_TOKEN },
  { id: 'provider-google-api-key', input: GOOGLE_KEY, secret: GOOGLE_KEY },
  { id: 'provider-stripe-key', input: STRIPE_KEY, secret: STRIPE_KEY },
  { id: 'provider-npm-token', input: NPM_TOKEN, secret: NPM_TOKEN },
  { id: 'assignment', input: `password = ${ASSIGNMENT_VALUE}`, secret: ASSIGNMENT_VALUE },
];

/** Near misses per value rule: none may be replaced. */
export const NEAR_MISSES: ReadonlyArray<string> = [
  '-----BEGIN PUBLIC KEY-----\nnot-a-private-key\n-----END PUBLIC KEY-----',
  'Bearer short',
  `ghp_${'Q'.repeat(35)}`,
  `github_pat_${'Z'.repeat(21)}`,
  `glpat-${'Y'.repeat(19)}`,
  'AKIAQWERTY',
  'xoxb-short',
  `AIza${'S'.repeat(34)}`,
  'sk_live_short',
  `npm_${'N'.repeat(35)}`,
  'author: bob',
];

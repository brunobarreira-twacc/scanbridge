export type RuleFile = { path: string; sha256: string };

export type SemgrepRules =
  | { mode: 'local'; files: RuleFile[] }
  | { mode: 'registry'; ids: string[] }
  | { mode: 'auto' };

export type Config = {
  version: 1;
  /** Additions only; sorted and deduplicated. Env values are checked at load time and never stored. */
  redaction: { headers: string[]; json_keys: string[]; env_vars: string[] };
  tools: {
    semgrep: {
      enabled: boolean;
      rules: SemgrepRules;
      ruleTimeoutSeconds: number;
      timeoutSeconds: number;
    };
    zap: {
      enabled: boolean;
      apiUrlEnv: string;
      apiKeyEnv: string;
      targetUrlEnv: string;
      /** Normalized origins, sorted and deduplicated. */
      allowedTargetOrigins: string[];
      sessionMode: 'require_clean' | 'reset';
      active: false;
      spiderTimeoutSeconds: number;
      passiveTimeoutSeconds: number;
    };
    sonarqube: {
      enabled: boolean;
      apiUrlEnv: string;
      apiKeyEnv: string;
      projectKeyEnv: string;
      timeoutSeconds: number;
    };
  };
};

/** Never carries a value from the file or the environment. */
export type ConfigError = { path: string; message: string };

export type Env = Readonly<Record<string, string | undefined>>;

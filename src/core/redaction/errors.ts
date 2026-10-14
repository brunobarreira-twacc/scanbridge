/** Thrown when a policy cannot be built. Messages name the variable and the rule, never a value. */
export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyError';
  }
}

/** Thrown when input is not redactable JSON or redaction cannot complete (fail closed). */
export class RedactionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RedactionError';
  }
}

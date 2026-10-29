import { canonicalJson } from './canonical-json.js';
import { sha256Hex } from './hash.js';

export type FingerprintMaterial = readonly (string | number)[];

/**
 * `fingerprint = "v1:" + lowercaseHex(sha256(utf8("v1:" + canonicalJson(material))))`.
 * Strings in the material are NFC-normalized before serialization.
 */
export function fingerprintFromMaterial(material: FingerprintMaterial): string {
  const normalized = material.map((item) => (typeof item === 'string' ? item.normalize('NFC') : item));
  return `v1:${sha256Hex(`v1:${canonicalJson(normalized)}`)}`;
}

/** Material for a Semgrep finding whose source range could be read (spec 04). */
export function semgrepExact(ruleId: string, path: string, canonicalSnippet: string): FingerprintMaterial {
  return ['semgrep', ruleId, path, canonicalSnippet];
}

/** Material for a Semgrep finding whose source could not be used (spec 04). */
export function semgrepDegraded(
  ruleId: string,
  path: string,
  startLine: number,
  startCol: number,
  endLine: number,
  endCol: number,
): FingerprintMaterial {
  return ['semgrep', ruleId, path, startLine, startCol, endLine, endCol];
}

/**
 * Material for a ZAP alert. `producerReference` is the sanitized `alertRef`, or
 * `""` when it is absent. `targetPath` comes from `normalizeUrl`.
 */
export function zap(
  ruleId: string,
  producerReference: string,
  method: string,
  targetPath: string,
  param: string,
): FingerprintMaterial {
  return ['zap', ruleId, producerReference, method, targetPath, param];
}

/** Material for a SonarQube finding when the issue hash is available (exact). */
export function sonarqube(ruleId: string, producerHash: string): FingerprintMaterial {
  return ['sonarqube', ruleId, producerHash];
}

/** Material for a SonarQube finding using source location when no hash is available (degraded). */
export function sonarqubeDegraded(ruleId: string, path: string, startLine: number): FingerprintMaterial {
  return ['sonarqube', ruleId, path, startLine];
}

/**
 * Canonical form of a redacted source snippet: BOM removed, NFC, CRLF and CR
 * to LF, every whitespace run collapsed to one space, trimmed.
 */
export function canonicalizeSnippet(text: string): string {
  const withoutBom = text.startsWith('﻿') ? text.slice(1) : text;
  return withoutBom
    .normalize('NFC')
    .replace(/\r\n?/g, '\n')
    .replace(/\s+/g, ' ')
    .trim();
}

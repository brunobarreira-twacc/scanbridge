import { NORMALIZED_JSON_MAX_BYTES, RAW_JSON_MAX_BYTES } from '../../contracts/limits.js';

/** [verify] V9: a size exactly at the limit is accepted; one byte over is not. */
export const rawTooLarge = (bytes: number): boolean => bytes > RAW_JSON_MAX_BYTES;
export const normalizedTooLarge = (bytes: number): boolean => bytes > NORMALIZED_JSON_MAX_BYTES;

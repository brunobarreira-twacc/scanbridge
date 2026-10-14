/**
 * `YYYYMMDDTHHMMSS.mmmZ-<first 8 hex of digest>` (spec 02). The caller supplies the clock value
 * and the digest of config and target; this function reads neither.
 */
export function makeScanId(date: Date, digestHex: string): string {
  if (Number.isNaN(date.getTime())) throw new RangeError('makeScanId: invalid date');
  const year = date.getUTCFullYear();
  if (year < 0 || year > 9999) throw new RangeError('makeScanId: year must be in 0000..9999');
  if (!/^[0-9a-f]{8,}$/.test(digestHex)) throw new TypeError('makeScanId: digest must be lowercase hex with at least 8 digits');

  const pad = (n: number, width: number) => String(n).padStart(width, '0');
  const stamp =
    pad(year, 4) +
    pad(date.getUTCMonth() + 1, 2) +
    pad(date.getUTCDate(), 2) +
    'T' +
    pad(date.getUTCHours(), 2) +
    pad(date.getUTCMinutes(), 2) +
    pad(date.getUTCSeconds(), 2) +
    '.' +
    pad(date.getUTCMilliseconds(), 3) +
    'Z';
  return `${stamp}-${digestHex.slice(0, 8)}`;
}

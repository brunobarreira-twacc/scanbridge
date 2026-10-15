# error-list-encoded

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run as a whole.
Sanitization: synthetic messages only.
Covers: list-encoded `type` values such as `["PartialParsing", …]`. The strongest element classifies the entry.
Verified shape: the first entry's `type` follows the nested form observed from Semgrep 1.180.0, `["PartialParsing", [{path,start,end}]]`, where the second element is a list of location objects. Semgrep exited 0, kept the file in `paths.scanned`, and Scanbridge returned partial/exit 4 with findings preserved. Only that `type` shape was observed; the `level`, `message` and the other three entries are synthetic.
Status: nested `PartialParsing` shape verified (V2). The other list-encoded entries remain unverified against real output.

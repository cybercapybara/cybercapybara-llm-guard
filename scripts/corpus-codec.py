#!/usr/bin/env python3
"""corpus-codec.py — decode/encode helper for tests/data/guard_rule_cases.yaml.

The 220 gitleaks-derived rules in that corpus store their `text`/
`expect_span`/negative fixtures as reversed-base64url (`text_b64` /
`expect_span_b64` / `negatives_b64`) rather than plaintext, because those
fixtures are, by design, shaped exactly like real provider secrets and trip
GitHub's server-side secret-scanning push protection when committed as
plaintext. See tests/unit/test_guard_rule_corpus.cpp's file-level doc comment
and task-1.9-report.md for the full rationale.

This script is stdlib-only (no PyYAML dependency) so it has no setup cost for
a reviewer. It does NOT do general YAML parsing -- it understands exactly the
flat, single-line-scalar shape tests/data/guard_rule_cases.yaml is generated
in (one `key: value` per line, `negatives_b64:` as a block list header
followed by `- value` items). It is not a general-purpose YAML tool.

Usage:
    # Print the whole corpus with every *_b64 field replaced by its decoded
    # plaintext (as a properly-quoted JSON/YAML string) -- for reviewing what
    # an encoded gitleaks fixture actually says without touching the file.
    python3 scripts/corpus-codec.py decode tests/data/guard_rule_cases.yaml

    # Encode a single fixture string the way the corpus generator would (for
    # hand-adding a new gitleaks-style positive/negative case).
    python3 scripts/corpus-codec.py encode 'some fixture text'

    # Inverse of encode -- decode a single on-disk token back to plaintext.
    python3 scripts/corpus-codec.py decode-token '<token from the yaml file>'
"""

import base64
import json
import re
import sys

_TEXT_B64_RE = re.compile(r'^(?P<indent>\s*)(?P<dash>-\s+)?text_b64:\s*(?P<val>\S+)\s*$')
_SPAN_B64_RE = re.compile(r'^(?P<indent>\s*)expect_span_b64:\s*(?P<val>\S+)\s*$')
_NEG_B64_EMPTY_RE = re.compile(r'^(?P<indent>\s*)negatives_b64:\s*\[\]\s*$')
_NEG_B64_HEADER_RE = re.compile(r'^(?P<indent>\s*)negatives_b64:\s*$')
_LIST_ITEM_RE = re.compile(r'^(?P<indent>\s*)-\s+(?P<val>\S+)\s*$')


def encode(s: str) -> str:
    """Reversed base64url (RFC 4648 sec.5, no padding) -- matches the corpus
    generator and Utils::Base64::url_decode-based C++ loader."""
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")[::-1]


def decode_token(token: str) -> str:
    reversed_token = token[::-1]
    padded = reversed_token + "=" * (-len(reversed_token) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8")


def decode_file(path: str) -> str:
    out_lines = []
    in_negatives_block = False
    negatives_indent = 0

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")

            if in_negatives_block:
                m = _LIST_ITEM_RE.match(line)
                # PyYAML's default block style puts list items at the SAME
                # indentation as their parent key (not indented further), so
                # this is >=, not >.
                if m and len(m.group("indent")) >= negatives_indent:
                    out_lines.append(f'{m.group("indent")}- {json.dumps(decode_token(m.group("val")))}')
                    continue
                in_negatives_block = False  # fall through: this line ends the block

            m = _TEXT_B64_RE.match(line)
            if m:
                dash = m.group("dash") or ""
                out_lines.append(f'{m.group("indent")}{dash}text: {json.dumps(decode_token(m.group("val")))}')
                continue

            m = _SPAN_B64_RE.match(line)
            if m:
                out_lines.append(f'{m.group("indent")}expect_span: {json.dumps(decode_token(m.group("val")))}')
                continue

            m = _NEG_B64_EMPTY_RE.match(line)
            if m:
                out_lines.append(f'{m.group("indent")}negatives: []')
                continue

            m = _NEG_B64_HEADER_RE.match(line)
            if m:
                out_lines.append(f'{m.group("indent")}negatives:')
                in_negatives_block = True
                negatives_indent = len(m.group("indent"))
                continue

            out_lines.append(line)

    return "\n".join(out_lines) + "\n"


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1

    cmd = argv[1]
    if cmd == "decode" and len(argv) == 3:
        sys.stdout.write(decode_file(argv[2]))
        return 0
    if cmd == "encode" and len(argv) == 3:
        print(encode(argv[2]))
        return 0
    if cmd == "encode" and len(argv) == 2:
        print(encode(sys.stdin.read().rstrip("\n")))
        return 0
    if cmd == "decode-token" and len(argv) == 3:
        print(decode_token(argv[2]))
        return 0

    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

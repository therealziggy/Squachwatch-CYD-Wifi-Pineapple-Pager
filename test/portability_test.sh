#!/bin/bash
# Static guards for BusyBox-incompatible constructs (the Pager's userland is BusyBox,
# but the dev box is GNU — these bugs pass locally and only bite on-device).
SW_PAYLOADS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads" && pwd)"
# 1) BusyBox tr has NO POSIX [:class:] support -> use ranges (a-z / A-Z) or octal (\001-\037).
#    Match a quoted class operand ('[: or "[:) so this rule doesn't trip on prose comments.
assert_empty "$(grep -rn "['\"]\[:" "$SW_PAYLOADS")" no_posix_tr_classes
# 2) BusyBox mktemp rejects a suffix after the XXXXXX template (e.g. sw.XXXXXX.db).
assert_empty "$(grep -rn 'XXXXXX\.' "$SW_PAYLOADS")" no_mktemp_suffix

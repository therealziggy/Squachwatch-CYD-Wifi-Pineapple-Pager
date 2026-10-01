#!/bin/bash
# Static guards for BusyBox-incompatible constructs (the Pager's userland is BusyBox,
# but the dev box is GNU — these bugs pass locally and only bite on-device).
SW_PAYLOADS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads" && pwd)"
# 1) BusyBox tr has NO POSIX [:class:] support -> use ranges (a-z / A-Z) or octal (\001-\037).
#    Match a quoted class operand ('[: or "[:) so this rule doesn't trip on prose comments.
assert_empty "$(grep -rn "['\"]\[:" "$SW_PAYLOADS")" no_posix_tr_classes
# 2) BusyBox mktemp rejects a suffix after the XXXXXX template (e.g. sw.XXXXXX.db).
assert_empty "$(grep -rn 'XXXXXX\.' "$SW_PAYLOADS")" no_mktemp_suffix

# The theme installer runs under BusyBox ash too.
SW_THEMES="$(cd "$(dirname "${BASH_SOURCE[0]}")/../themes" && pwd)"
assert_empty "$(grep -rn "['\"]\[:" "$SW_THEMES")" no_posix_tr_classes_in_themes
assert_empty "$(grep -rn 'XXXXXX\.' "$SW_THEMES")" no_mktemp_suffix_in_themes
assert_empty "$(grep -rn 'head -c' "$SW_THEMES")" no_head_c_in_themes
assert_contains "$(ls "$SW_THEMES/SquachWatch")" "install.sh" portability_walk_reads_themes

# lib/remoteid.sh's awk must not use 0x.. literals: BusyBox awk and mawk do not parse them. Comments, and
# the tcpdump filter (a tcpdump expression, not awk), are left out of the check.
assert_empty "$(sed 's/#.*//' "$SW_PAYLOADS/user/reconnaissance/squachwatch/lib/remoteid.sh" | grep -vF "REPLY='type mgt" | grep -nE '(^|[^0-9a-zA-Z_])0x[0-9a-fA-F]')" remoteid_no_hex_literals
# control: the check does see a planted literal
assert_contains "$(printf 'if (b(i) == 0xfa) x\n' | sed 's/#.*//' | grep -nE '(^|[^0-9a-zA-Z_])0x[0-9a-fA-F]')" "0xfa" remoteid_hex_check_works

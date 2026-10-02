#!/bin/bash
# lib/remoteid.sh — Remote ID over WiFi (spec docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md).
# Drones broadcast Remote ID (their ID, position and the pilot's location) in WiFi beacons and in NAN
# action frames. Each lap a short, read-only tcpdump window on the recon radio feeds ONE awk pass, which
# decodes those frames into one line per transmitter address, written as integers, empty fields or
# lowercase hex only: Remote ID is not authenticated, so no broadcast byte may shift a field. Bash then
# does the units, the cleaning (sw_sanitize_ident), the remoteid.csv rows and the detections.

# --- The decoder: tcpdump -t -nn -xx text in; one line per drone, then a stats line, out (spec §6.2) ---
#   D<TAB>mac rssi forms id_type id_hex id2_type id2_hex ua_type status lat lon alt_geo alt_baro height
#        height_ref speed vspeed heading pilot_type pilot_lat pilot_lon pilot_alt operator_id_hex self_id_hex
#   S<TAB>frames<TAB>understood<TAB>rid_frames<TAB>more_drones
# forms is a bit mask: the forms heard (1 ASD-STAN beacon, 2 NAN, 4 Parrot beacon), plus 8 when the address sent
# more distinct Basic IDs than the two kept (id and id2: the first two that hold text, distinct by text or type).
# The stats line comes LAST, at the end of the input: a pass without one did not finish (sw_rid_collect).
# Its inputs: max (SW_RID_MAX_DRONES: at most that many D lines, 0 = no cap) and ignkeys, the ignore list's drone:
# lines as keys (_sw_rid_keys), with which it chooses which addresses to keep when there are more than max: those
# the list may silence come last (emit). The keys only order the lines; sw_rid_records alone silences.
_sw_rid_awk_src() { cat <<'RIDAWK'
# One frame per tcpdump header line; the hex lines that follow start with an offset like 0x0010:.
# Every byte test uses a decimal literal: BusyBox awk and mawk do not parse 0x.. constants.
function b(i) { return hx[substr(hex, 1 + i * 2, 1)] * 16 + hx[substr(hex, 2 + i * 2, 1)] }
function le16(i) { return b(i) + b(i + 1) * 256 }
function s32(i,  v) { v = b(i) + b(i + 1) * 256 + b(i + 2) * 65536 + b(i + 3) * 16777216; return v >= 2147483648 ? v - 4294967296 : v }
function s8(i,  v) { v = b(i); return v >= 128 ? v - 256 : v }
function nb() { return length(hex) / 2 }
function bit(x, k) { return int(x / k) % 2 }                 # k = 1, 2, 4, 8, ...
# hex of a text field: cut at the first zero byte (a C string), trailing spaces dropped
# (redundant: "i + j < nb()" below; okpack already keeps every message inside the frame)
function txt(i, n,  r, c, j) { r = ""
  for (j = 0; j < n && i + j < nb(); j++) { c = b(i + j); if (c == 0) break; r = r sprintf("%02x", c) }
  while (length(r) >= 2 && substr(r, length(r) - 1) == "20") r = substr(r, 1, length(r) - 2)
  return r }
function hexall(i, n,  r, j) { r = ""; for (j = 0; j < n; j++) r = r sprintf("%02x", b(i + j)); return r }
# both 0 is the standard's "unknown"; out of range is garbage
function okll(a, o) { return !(a == 0 && o == 0) && a >= -900000000 && a <= 900000000 && o >= -1800000000 && o <= 1800000000 }
function okpack(pk, end,  c) { if (pk + 3 > end) return 0   # redundant: the fit check below covers it
  if (int(b(pk) / 16) != 15 || b(pk + 1) != 25) return 0
  c = b(pk + 2); if (c < 1 || c > 9) return 0
  return pk + 3 + 25 * c <= end }
BEGIN { for (k = 0; k <= 9; k++) hx[k] = k; hx["a"] = 10; hx["b"] = 11; hx["c"] = 12; hx["d"] = 13; hx["e"] = 14; hx["f"] = 15
  # the ignore list's keys (_sw_rid_keys), each after a ":", so that a key of "" is one too; ch: digits and letters
  nk = split(ignkeys, kw, " "); for (k = 1; k <= nk; k++) ign[substr(kw[k], 2)] = 1
  for (k = 0; k <= 9; k++) ch[48 + k] = k; for (k = 1; k <= 26; k++) ch[64 + k] = substr("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k, 1) }
$1 !~ /^0x[0-9a-f]+:$/ { if (hex != "") decode(); hex = ""; sig = ""
  # tcpdump prints the radiotap fields before any frame text, so a network name cannot supply this. A radiotap
  # signal is one signed byte: a match outside -128..127 came from frame text (a radio with no signal field)
  if (match($0, /-?[0-9]+dBm signal/)) { sig = substr($0, RSTART, RLENGTH - 10)
    if (sig !~ /^(0|-?[1-9][0-9]?[0-9]?)$/ || sig + 0 < -128 || sig + 0 > 127) sig = "" }
  next }
{ for (k = 2; k <= NF; k++) hex = hex $k }
END { if (hex != "") decode(); emit() }
function decode(  off, fc, hl, ie, id, ln, f, i, pk, steps) {
  frames++
  if (length(hex) % 2) return
  off = le16(2)                                              # the radiotap length = where 802.11 starts
  if (b(0) != 0 || off < 8 || off + 24 > nb()) return       # redundant: "off + 24 > nb()" (the header check below)
  fc = b(off); fc = fc - fc % 4                              # frame control, version bits masked
  if (fc != 128 && fc != 208) return                         # beacon or action frame only
  hl = (b(off + 1) >= 128) ? 28 : 24                         # 4 more header bytes when the Order bit is set
  if (off + hl > nb()) return
  understood++
  # cheap pre-test: only a frame holding ASD-STAN FA0BBC0D, the Parrot OUI or the NAN service id hash gets the walk
  # (redundant for what is decoded, which the walk alone decides: it is there for speed)
  if (!index(hex, "fa0bbc0d") && !index(hex, "903ae6") && !index(hex, "8869199d9209")) return
  if (fc == 128) { ie = off + hl + 12                        # beacon: walk its elements
    # at most 64 elements per frame (redundant: "ie + 2 <= nb()", the next line's check covers it)
    while (ie + 2 <= nb() && steps++ < 64) { id = b(ie); ln = b(ie + 1)
      if (ie + 2 + ln > nb()) break                          # one running past the end ends the walk
      if (id == 221 && ln >= 8) { f = 0                       # redundant: "ln >= 8" (okpack needs more)
        if (b(ie + 2) == 250 && b(ie + 3) == 11 && b(ie + 4) == 188 && b(ie + 5) == 13) f = 1   # ASD-STAN FA:0B:BC, 0x0D
        else if (b(ie + 2) == 144 && b(ie + 3) == 58 && b(ie + 4) == 230) f = 4               # Parrot 90:3A:E6
        if (f && okpack(ie + 7, ie + 2 + ln)) { take(off + 10, ie + 7, f); return } }       # OUI, type, counter
      ie = ie + 2 + ln }
    return }
  # NAN: to 51:6F:9A:01:00:00, then public action / vendor specific / Wi-Fi Alliance / NAN
  if (b(off + 4) != 81 || b(off + 5) != 111 || b(off + 6) != 154 || b(off + 7) != 1 || b(off + 8) != 0 || b(off + 9) != 0) return
  i = off + hl
  if (b(i) != 4 || b(i + 1) != 9 || b(i + 2) != 80 || b(i + 3) != 111 || b(i + 4) != 154 || b(i + 5) != 19) return
  i = i + 6                                                  # the NAN attributes: id, 2-byte length, body
  # at most 64 attributes per frame (redundant: "i + 3 <= nb()", the next line's check covers it)
  while (i + 3 <= nb() && steps++ < 64) { ln = le16(i + 1)
    if (i + 3 + ln > nb()) break
    # a Service Descriptor holding the service id hash (redundant: "ln >= 9", nanpack bounds its own reads)
    if (b(i) == 3 && ln >= 9 && b(i + 3) == 136 && b(i + 4) == 105 && b(i + 5) == 25 && b(i + 6) == 157 && b(i + 7) == 146 && b(i + 8) == 9) {
      pk = nanpack(i + 9, i + 3 + ln)                        # just after the service id hash
      if (pk && okpack(pk, sie)) { take(off + 10, pk, 2); return } }
    i = i + 3 + ln }
}
# after the service id: instance, requestor, control, the optional fields control announces, then
# the service info (length, counter, pack). Returns the pack's offset (0 = none); sie = its end.
function nanpack(p, end,  c) { if (p + 3 > end) return 0   # redundant: the service-info checks cover it
  c = b(p + 2); p = p + 3
  if (bit(c, 64)) p = p + 2                                  # binding bitmap
  # (redundant below: both "p >= end", which the service-info check covers, and its "p + 2 > end", which
  # "sie > end" and okpack cover)
  if (bit(c, 4)) { if (p >= end) return 0; p = p + 1 + b(p) } # matching filter
  if (bit(c, 8)) { if (p >= end) return 0; p = p + 1 + b(p) } # service response filter
  if (!bit(c, 16) || p + 2 > end) return 0                   # service info present?
  sie = p + 1 + b(p); if (sie > end) return 0
  return p + 2 }
function take(a, pk, f,  m, c, n, i, t, v, w, y) { m = hexall(a, 6)
  if (!(m in seen)) { seen[m] = 1; ord[++no] = m }
  if (sig != "" && (!(m in rs) || sig + 0 > rs[m] + 0)) rs[m] = sig
  if (!bit(fm[m] + 0, f)) fm[m] = fm[m] + f
  ridf++
  c = b(pk + 2)
  for (n = 0; n < c; n++) { i = pk + 3 + 25 * n; t = int(b(i) / 16)
    if (t == 0) { v = txt(i + 2, 20); y = int(b(i + 1) / 16)   # Basic ID: y = its ID type
      if (!(m in ua)) ua[m] = b(i + 1) % 16                    # the airframe: the first Basic ID's
      # The first two distinct IDs (another text or another ID type) are kept; one with no text takes no place.
      # One more distinct ID flags the address (forms bit 8): it sent more IDs than are kept, and a spoofer
      # heard first may have taken both places (sw_rid_records never silences it)
      if (v != "") {
        if (nbi[m] + 0 == 0) { it1[m] = y; ih1[m] = v; nbi[m] = 1 }
        else if (v != ih1[m] || y != it1[m]) {
          if (nbi[m] == 1) { it2[m] = y; ih2[m] = v; nbi[m] = 2 }
          else if (v != ih2[m] || y != it2[m]) xi[m] = 8 } } }
    else if (t == 1) { st[m] = int(b(i + 1) / 16); hr[m] = bit(b(i + 1), 4)
      v = b(i + 2) + (bit(b(i + 1), 2) ? 180 : 0); hd[m] = (v > 360) ? "" : v
      v = b(i + 3); sp[m] = bit(b(i + 1), 1) ? ((v == 255) ? "" : v * 75 + 6375) : v * 25
      v = s8(i + 4); vs[m] = (v >= 126 || v <= -126) ? "" : v * 5
      v = s32(i + 5); w = s32(i + 9); if (okll(v, w)) { la[m] = v; lo[m] = w } else { la[m] = ""; lo[m] = "" }
      v = le16(i + 13); ab[m] = v ? v : ""; v = le16(i + 15); ag[m] = v ? v : ""; v = le16(i + 17); ht[m] = v ? v : "" }
    else if (t == 3) si[m] = txt(i + 2, 23)
    else if (t == 4) { pt[m] = b(i + 1) % 4
      v = s32(i + 2); w = s32(i + 6); if (okll(v, w)) { pa[m] = v; po[m] = w } else { pa[m] = ""; po[m] = "" }
      v = le16(i + 18); pl[m] = v ? v : "" }
    else if (t == 5) oi[m] = txt(i + 2, 20) }
}
function line(m) {
  print "D\t" m "\t" rs[m] "\t" (fm[m] + xi[m]) "\t" it1[m] "\t" ih1[m] "\t" it2[m] "\t" ih2[m] "\t" ua[m] "\t" st[m] \
    "\t" la[m] "\t" lo[m] "\t" ag[m] "\t" ab[m] "\t" ht[m] "\t" hr[m] "\t" sp[m] "\t" vs[m] "\t" hd[m] \
    "\t" pt[m] "\t" pa[m] "\t" po[m] "\t" pl[m] "\t" oi[m] "\t" si[m] }
# An ID's key: the ASCII letters and digits of hex text h, upper case. sw_rid_records compares an ID's whole
# cleaned text, without spaces and upper-cased in the C locale, and the cleaning only removes bytes that are
# neither: so an ID bash finds listed has a listed key, while a near miss (the same ID with a dash, say) has one too
# without being listed.
function idkey(h,  r, j, c) { r = ""
  for (j = 1; j < length(h); j += 2) { c = hx[substr(h, j, 1)] * 16 + hx[substr(h, j + 1, 1)]
    if (c >= 97 && c <= 122) c = c - 32
    if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90)) r = r ch[c] }
  return r }
# Does hex text h clean to nothing in sw_rid_records? Its steps, byte for byte: sw_sanitize_ident in the C locale
# ("|", the C0 controls and DEL; then the C1 controls, c2 80..9f; then U+2028/2029, e2 80 a8/a9; each step on what
# the one before left), then the spaces at both ends trimmed, so only spaces may be left. A byte that no step can
# remove and that is no space ends it at once (the rest is only there for the bytes some step can remove).
function blank(h,  j, c, s, u) { s = ""; u = ""
  for (j = 1; j < length(h); j += 2) { c = hx[substr(h, j, 1)] * 16 + hx[substr(h, j + 1, 1)]
    if (c > 32 && c != 124 && c != 127 && c != 194 && c != 226 && c != 168 && c != 169 && (c < 128 || c > 159)) return 0
    if (c >= 32 && c != 124 && c != 127) s = s substr(h, j, 2) }
  for (j = 1; j < length(s); j += 2) {
    c = (j + 2 < length(s)) ? hx[substr(s, j + 2, 1)] * 16 + hx[substr(s, j + 3, 1)] : 0
    if (substr(s, j, 2) == "c2" && c >= 128 && c <= 159) j += 2; else u = u substr(s, j, 2) }
  for (j = 1; j < length(u); j += 2) {
    if (substr(u, j, 6) == "e280a8" || substr(u, j, 6) == "e280a9") j += 4
    else if (substr(u, j, 2) != "20") return 0 }
  return 1 }
# Can the ignore list silence address m (sw_rid_records)? Never when it is flagged (forms bit 8). Else every kept ID
# that bash would name the drone by (one with a letter or digit, or any other that does not clean to nothing: a
# binary UUID, a punctuation-only or non-Latin ID) must have its key listed (an ID with neither has the key "",
# which only a listed ID with neither gives); with no such ID, bash goes by the address (drone:<MAC>). So every
# drone bash silences answers yes, and one it reports answers yes only as a near miss: an ID that differs from a
# listed one only in characters other than ASCII letters and digits.
function ignorable(m,  n, k) { if (xi[m]) return 0
  n = 0; k = idkey(ih1[m])
  if (k != "" || !blank(ih1[m])) { if (!(k in ign)) return 0; n++ }
  k = idkey(ih2[m])
  if (k != "" || !blank(ih2[m])) { if (!(k in ign)) return 0; n++ }
  return n ? 1 : (toupper(m) in ign) }
# The strongest signals first, at most max of them (0 = no cap: all, as heard); a missing signal counts as
# weakest. When choosing them, the addresses the ignore list may silence come after all the others (re-review
# 2026-10-02: 32 louder copies of a listed ID took every place, and were then silenced): sc, worked out once per
# address, is the signal less 10000 for those. This only orders: every line chosen is printed, and only
# sw_rid_records silences. (With no key, nothing is ignorable, so nothing is looked up.)
function emit(  k, j, best, bs, kept) { kept = 0
  if (max + 0 == 0) { for (k = 1; k <= no; k++) line(ord[k]); kept = no }
  else { for (j = 1; j <= no; j++) sc[j] = ((ord[j] in rs) ? rs[ord[j]] + 0 : -999) - ((nk && ignorable(ord[j])) ? 10000 : 0)
    for (k = 1; k <= no && kept < max + 0; k++) { best = 0
      for (j = 1; j <= no; j++) if (!used[j] && (!best || sc[j] > bs)) { best = j; bs = sc[j] }
      used[best] = 1; kept++; line(ord[best]) } }
  # last: the stats line, which tells sw_rid_collect that the pass finished
  print "S\t" frames + 0 "\t" understood + 0 "\t" ridf + 0 "\t" no - kept }
RIDAWK
}
# stdin = tcpdump -t -nn -xx text -> the lines above; at most SW_RID_MAX_DRONES D lines (0 = no cap), those the
# ignore list (SW_IGNORE_SET) may silence chosen last
_sw_rid_decode_awk() { _sw_rid_keys; awk -v max="${SW_RID_MAX_DRONES:-32}" -v ignkeys="$REPLY" "$(_sw_rid_awk_src)"; }
# The ignore list's drone: lines (drone:<ID>, drone:<MAC>) as the decoder's keys -> REPLY: each one's ASCII letters
# and digits in upper case, after a ":" (one with neither is ":" alone), e.g. " :0000FSWTESTOWNER001 :80E126AABBCC ".
# The list is split into words on spaces, tabs and line breaks (sw_ignored only ever matches a whole word) and
# nothing in it is expanded; a bare "DRONE:" silences nothing and gives no key. The letters and digits are named
# one by one, not as ranges (en_US.UTF-8's ranges keep dotless ı and long ſ, which ^^ makes I and S), and only they
# and ":" reach awk -v, which would read a backslash as an escape. Once per lap, builtins only, linear in the list.
_sw_rid_keys() {
  local LC_ALL=C w words
  REPLY=" "
  IFS=$' \t\n' read -r -d '' -a words <<< "${SW_IGNORE_SET:-}" || :   # status 1 at the list's end: not a failure
  for w in "${words[@]}"; do
    case "$w" in
      DRONE:?*) w="${w#DRONE:}"; w="${w//[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]/}"
                REPLY+=":${w^^} " ;;
    esac
  done
}

# --- From the decoder's lines to detections and remoteid.csv rows (spec §6.3, §6.5) ---
# Formatters: builtins only, bash integer arithmetic (no floats), answer in REPLY.
sw_rid_coord() {   # $1 = raw 1e7 int, $2 = decimals (1-7) -> REPLY; "" when $1 is empty
  local r="$1" sign="" a frac
  case "$r" in -*) sign="-"; a="${r#-}" ;; *) a="$r" ;; esac
  case "$a" in ''|*[!0-9]*) REPLY=""; return ;; esac
  printf -v frac '%07d' $(( a % 10000000 ))
  REPLY="$sign$(( a / 10000000 )).${frac:0:$2}"
}
sw_rid_alt() {     # $1 = raw uint16 encoding -> REPLY metres (enc * 0.5 - 1000), one decimal
  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
  local d=$(( $1 * 5 - 10000 )) sign="" a
  case "$d" in -*) sign="-"; a="${d#-}" ;; *) a="$d" ;; esac
  REPLY="$sign$(( a / 10 )).$(( a % 10 ))"
}
sw_rid_m() {       # $1 = raw uint16 encoding -> REPLY whole metres, rounded (the screen)
  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
  local d=$(( $1 * 5 - 10000 ))
  if [ "$d" -ge 0 ]; then REPLY=$(( (d + 5) / 10 )); else REPLY=-$(( (5 - d) / 10 )); fi
}
sw_rid_mps() {     # $1 = centi-m/s -> REPLY whole m/s, rounded (the screen)
  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
  REPLY=$(( ($1 + 50) / 100 ))
}
sw_rid_mps2() {    # $1 = centi-m/s -> REPLY m/s, two decimals (the CSV)
  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
  printf -v REPLY '%d.%02d' $(( $1 / 100 )) $(( $1 % 100 ))
}
sw_rid_dmps() {    # $1 = signed deci-m/s -> REPLY m/s, one decimal (the CSV)
  local d="$1" sign="" a
  case "$d" in -*) sign="-"; a="${d#-}" ;; *) a="$d" ;; esac
  case "$a" in ''|*[!0-9]*) REPLY=""; return ;; esac
  REPLY="$sign$(( a / 10 )).$(( a % 10 ))"
}
sw_rid_text() {    # $1 = lowercase hex -> REPLY = text, cleaned by sw_sanitize_ident (the one boundary), and
  # only then trimmed of spaces at both ends, so a control byte cannot shield one (all spaces: no text at all)
  local h="$1" e="" i
  for (( i = 0; i + 1 < ${#h}; i += 2 )); do e+="\\x${h:i:2}"; done
  printf -v REPLY '%b' "$e"
  sw_sanitize_ident "$REPLY"
  REPLY="${REPLY#"${REPLY%%[! ]*}"}"; REPLY="${REPLY%"${REPLY##*[! ]}"}"
}
_sw_rid_name() {   # $1 = table, $2 = code -> REPLY = the standard's name, or the code when not in the table
  REPLY="$2"
  case "$1:$2" in
    id:0) REPLY=none ;; id:1) REPLY=serial ;; id:2) REPLY=caa ;; id:3) REPLY=utm ;; id:4) REPLY=session ;;
    ua:0) REPLY=none ;; ua:1) REPLY=aeroplane ;; ua:2) REPLY=multirotor ;; ua:3) REPLY=gyroplane ;; ua:4) REPLY=vtol ;;
    ua:5) REPLY=ornithopter ;; ua:6) REPLY=glider ;; ua:7) REPLY=kite ;; ua:8) REPLY="free balloon" ;;
    ua:9) REPLY="captive balloon" ;; ua:10) REPLY=airship ;; ua:11) REPLY=parachute ;; ua:12) REPLY=rocket ;;
    ua:13) REPLY=tethered ;; ua:14) REPLY="ground obstacle" ;; ua:15) REPLY=other ;;
    st:0) REPLY=undeclared ;; st:1) REPLY=ground ;; st:2) REPLY=airborne ;; st:3) REPLY=emergency ;; st:4) REPLY=failure ;;
    hr:0) REPLY=takeoff ;; hr:1) REPLY=ground ;;
    pl:0) REPLY=takeoff ;; pl:1) REPLY=live ;; pl:2) REPLY=fixed ;;
  esac
}
# A D line's 24 fields, each checked before use (no leading zeros either: bash reads those as octal)
_sw_rid_line_ok() {
  [ -z "$extra" ] || return 1                               # a | inside a field split it: not the decoder's line
  local n='-?[1-9][0-9]{0,9}|0' u='[1-9][0-9]{0,4}' h='([0-9a-f]{2})'
  # forms: 1 to 15, but not 8 (the flag alone: every address the decoder reports was heard in some form)
  [[ "$mac" =~ ^[0-9a-f]{12}$ && "$rssi" =~ ^(-?[1-9][0-9]{0,2}|0)?$ && "$forms" =~ ^([1-79]|1[0-5])$ ]] || return 1
  [[ "$it1" =~ ^([0-9]|1[0-5])?$ && "$it2" =~ ^([0-9]|1[0-5])?$ && "$ua" =~ ^([0-9]|1[0-5])?$ ]] || return 1
  [[ "$st" =~ ^([0-9]|1[0-5])?$ && "$hr" =~ ^[01]?$ && "$pt" =~ ^[0-3]?$ ]] || return 1
  [[ "$ih1" =~ ^$h{0,20}$ && "$ih2" =~ ^$h{0,20}$ && "$oi" =~ ^$h{0,20}$ && "$si" =~ ^$h{0,23}$ ]] || return 1
  [[ "$la" =~ ^($n)?$ && "$lo" =~ ^($n)?$ && "$pa" =~ ^($n)?$ && "$po" =~ ^($n)?$ ]] || return 1
  [[ "$ag" =~ ^($u)?$ && "$ab" =~ ^($u)?$ && "$ht" =~ ^($u)?$ && "$pl" =~ ^($u)?$ ]] || return 1
  [[ "$sp" =~ ^(0|[1-9][0-9]{0,4})?$ && "$vs" =~ ^(-?[1-9][0-9]{0,2}|0)?$ && "$hd" =~ ^(0|[1-9][0-9]{0,2})?$ ]]
}
# sw_rid_records <now> <loot dir>: stdin = the decoder's lines (only D lines are used) -> one remoteid.csv row
# per drone, and one detection per drone on stdout:
#   drone_rid|Drone|high|surveillance|wifi|<MAC>|<ID or empty>|<rssi>|<airframe>TAB<motion>TAB<pilot>
sw_rid_records() {
  local now="$1" csv="${SW_RID_FILE:-$2/remoteid.csv}" gps="" gps_read=0 line tabs
  local tag mac rssi forms it1 ih1 it2 ih2 ua st la lo ag ab ht hr sp vs hd pt pa po pl oi si extra
  local MAC idt id idt2 id2 t1 t2 ls1 ls2 form air motion pilot detail
  local LC_ALL=C
  while IFS= read -r line || [ -n "$line" ]; do
    [ "${line:0:2}" = $'D\t' ] || continue
    tabs="${line//[^$'\t']/}"; [ "${#tabs}" -eq 24 ] || continue
    # TAB is whitespace to `read`, so runs of empty fields would collapse: split on | (no field holds one)
    IFS='|' read -r tag mac rssi forms it1 ih1 it2 ih2 ua st la lo ag ab ht hr sp vs hd pt pa po pl oi si extra <<< "${line//$'\t'/|}"
    _sw_rid_line_ok || continue
    sw_stopped && return 0
    if [ "$gps_read" -eq 0 ]; then gps="$(GPS_GET 2>/dev/null | tr ' ' ',')"; gps_read=1; fi
    sw_wifi_colonize "$mac"; MAC="$REPLY"
    # the drone's ID: the first one it sent with any text, a serial number (ID type 1) preferred; the other
    # one, if any, is its second ID. An empty ID, or one of spaces only, is no ID.
    sw_rid_text "$ih1"; t1="$REPLY"; sw_rid_text "$ih2"; t2="$REPLY"
    if [ -n "$t2" ] && { [ -z "$t1" ] || { [ "$it2" = 1 ] && [ "$it1" != 1 ]; }; }; then
      idt="$it2"; id="$t2"; idt2="$it1"; id2="$t1"
    else idt="$it1"; id="$t1"; idt2="$it2"; id2="$t2"; fi
    # The owner's own drone (ignore.txt) leaves no trace, but only when EVERY ID it sent is listed as
    # drone:<ID>, or, when it sent none, its address as drone:<MAC>: a spoofer can send a copy of the owner's ID
    # from another drone's address, and must not hide that drone with it (spec §4). And never when the address
    # sent more IDs than the decoder keeps (forms bit 8): a spoofer heard first can fill both kept IDs with the
    # owner's, so the other drone's own ID is the one not kept. id is empty only when id2 is. ls1/ls2: listed.
    ls1=0; ls2=0
    sw_ignored "drone_rid|Drone|high|surveillance|wifi|$MAC|$id|$rssi" "${SW_IGNORE_SET:-}" && ls1=1
    [ -n "$id2" ] && sw_ignored "drone_rid|Drone|high|surveillance|wifi|$MAC|$id2|$rssi" "${SW_IGNORE_SET:-}" && ls2=1
    if [ $(( forms & 8 )) -eq 0 ] && [ "$ls1" = 1 ] && { [ -z "$id2" ] || [ "$ls2" = 1 ]; }; then continue; fi
    # One of its two IDs listed and the other not: it is named by the one NOT listed (spec §3), on screen, in the
    # alert, its ledger key and remoteid.csv. Named by the owner's own ID, it would read as the owner's drone.
    if [ "$ls1" = 1 ] && [ "$ls2" = 0 ] && [ -n "$id2" ]; then
      t1="$id"; id="$id2"; id2="$t1"; t1="$idt"; idt="$idt2"; idt2="$t1"   # swapped through t1, free by now
    fi
    form=""; [ $(( forms & 1 )) -ne 0 ] && form=beacon
    [ $(( forms & 2 )) -ne 0 ] && form="${form:+$form+}nan"; [ $(( forms & 4 )) -ne 0 ] && form="${form:+$form+}parrot"
    # the screen and alert detail: airframe (nothing for a declared "none"), motion, pilot
    air=""; [ -n "$ua" ] && [ "$ua" != 0 ] && { _sw_rid_name ua "$ua"; air="$REPLY"; }
    motion=""
    if [ -n "$ht" ]; then sw_rid_m "$ht"; motion="${REPLY}m up"
    elif [ -n "$ag" ]; then sw_rid_m "$ag"; motion="alt ${REPLY}m"; fi
    [ -n "$sp" ] && { sw_rid_mps "$sp"; motion="${motion:+$motion, }${REPLY}m/s"; }
    # more IDs than kept: said first in the motion piece, the piece that is both on the screen line and in the alert
    [ $(( forms & 8 )) -ne 0 ] && motion="also sends other IDs${motion:+, $motion}"
    pilot="no pilot location"
    if [ -n "$pa" ] && [ -n "$po" ]; then
      case "$pt" in 0) pilot="takeoff point" ;; 1) pilot="pilot (live)" ;; 2) pilot="pilot (fixed)" ;; *) pilot="pilot" ;; esac
      sw_rid_coord "$pa" 5; pilot+=" $REPLY"; sw_rid_coord "$po" 5; pilot+=",$REPLY"
    fi
    detail="$air"$'\t'"$motion"$'\t'"$pilot"
    # a Stop meanwhile (the first drone waited for the GPS read above, a gpsd query on the Pager): no row and no
    # detection (spec §7.3)
    sw_stopped && return 0
    _sw_rid_csv_row
    printf 'drone_rid|Drone|high|surveillance|wifi|%s|%s|%s|%s\n' "$MAC" "$id" "$rssi" "$detail"
  done
}
# one remoteid.csv row from sw_rid_records' variables (dynamic scope); the header is written first
_sw_rid_csv_row() {
  local r
  [ -f "$csv" ] || printf '%s\n' "time,form,mac,rssi,id_type,id,id2_type,id2,ua_type,status,lat,lon,alt_geo_m,alt_baro_m,height_m,height_ref,speed_mps,vspeed_mps,heading_deg,pilot_loc,pilot_lat,pilot_lon,pilot_alt_m,operator_id,self_id,gps" > "$csv"
  r="$now,$form,$MAC,$rssi"
  if [ -n "$id" ]; then _sw_rid_name id "$idt"; r+=",$REPLY"; else r+=","; fi
  _sw_csv_cell "$id"; r+=",$REPLY"
  if [ -n "$id2" ]; then _sw_rid_name id "$idt2"; r+=",$REPLY"; else r+=","; fi
  _sw_csv_cell "$id2"; r+=",$REPLY"
  if [ -n "$ua" ]; then _sw_rid_name ua "$ua"; r+=",$REPLY"; else r+=","; fi
  if [ -n "$st" ]; then _sw_rid_name st "$st"; r+=",$REPLY"; else r+=","; fi
  sw_rid_coord "$la" 7; r+=",$REPLY"; sw_rid_coord "$lo" 7; r+=",$REPLY"
  sw_rid_alt "$ag"; r+=",$REPLY"; sw_rid_alt "$ab"; r+=",$REPLY"; sw_rid_alt "$ht"; r+=",$REPLY"
  if [ -n "$hr" ]; then _sw_rid_name hr "$hr"; r+=",$REPLY"; else r+=","; fi
  sw_rid_mps2 "$sp"; r+=",$REPLY"; sw_rid_dmps "$vs"; r+=",$REPLY"; r+=",$hd"
  if [ -n "$pt" ]; then _sw_rid_name pl "$pt"; r+=",$REPLY"; else r+=","; fi
  sw_rid_coord "$pa" 7; r+=",$REPLY"; sw_rid_coord "$po" 7; r+=",$REPLY"; sw_rid_alt "$pl"; r+=",$REPLY"
  sw_rid_text "$oi"; _sw_csv_cell "$REPLY"; r+=",$REPLY"
  sw_rid_text "$si"; _sw_csv_cell "$REPLY"; r+=",$REPLY"
  _sw_csv_cell "$gps"; r+=",$REPLY"
  printf '%s\n' "$r" >> "$csv"
}
# --- The per-lap capture: a bounded tcpdump window, run like btmon in lib/ble.sh (spec §6.1, §7.2) ---
# The kernel filter: beacons, and action frames sent to NAN's address. BPF cannot look inside a beacon's
# element list, so the decoder picks out the Remote ID beacons. ("subtype action" does not parse on the
# Pager's libpcap; the frame-control byte does.)
_sw_rid_filter() { REPLY='type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)'; }

# A WARN when the capture's status changes, like the BLE note. The two "partly blind" ones (capped: the frame
# cap; lost: frames dropped by the kernel or lost on the way) share one WARN per SW_COOLDOWN and recover
# silently. After an OFF status (capture_failed, not_understood) the next lap that captures, ok or partly blind,
# says it recovered. $1 = ok | capture_failed | not_understood | capped | lost, $2 = now (epoch).
# Once the payload is stopped: no line and no state file (the exit trap has removed it; spec §7.3).
sw_rid_health_note() {
  local st="$1" now="$2" sf="${SW_RID_STATE_FILE:-${SW_TMP_DIR:-/tmp}/sw_rid.state}" prev="" capt="" cd="${SW_COOLDOWN:-600}"
  [ -f "$sf" ] && { read -r prev; read -r capt; } < "$sf"
  case "$cd" in ''|*[!0-9]*) cd=600 ;; esac
  [[ "$capt" =~ ^[1-9][0-9]{0,11}$ ]] || capt=""
  case "$st" in
    capped|lost)
      case "$prev" in capture_failed|not_understood) _sw_rid_say green "Remote ID capture recovered" ;; esac
      if [ -z "$capt" ] || [ "$now" -lt "$capt" ] || [ $(( now - capt )) -ge "$cd" ]; then
        if [ "$st" = capped ]; then _sw_rid_say yellow "WARN: WiFi capture hit its frame limit (beacon flood?) — Remote ID partly blind"
        else _sw_rid_say yellow "WARN: WiFi capture lost frames (CPU busy?) — Remote ID partly blind"; fi
        capt="$now"
      fi ;;
    ok) case "$prev" in capture_failed|not_understood) _sw_rid_say green "Remote ID capture recovered" ;; esac ;;
    capture_failed) [ "$prev" = capture_failed ] || _sw_rid_say yellow "WARN: WiFi capture failed — Remote ID over WiFi OFF" ;;
    not_understood) [ "$prev" = not_understood ] || _sw_rid_say yellow "WARN: WiFi capture not understood — Remote ID over WiFi OFF" ;;
  esac
  sw_stopped && return 0
  printf '%s\n%s\n' "$st" "$capt" > "$sf"
}
# a line on the Pager's screen, unless the payload has been stopped (the screen is a relaunch's by then)
_sw_rid_say() { sw_stopped || LOG "$@" 2>/dev/null; }

# $1 = the lap's start (epoch). Starts this lap's capture in the background and leaves SW_RID_PID,
# SW_RID_CAP and SW_RID_ERR for sw_rid_collect, which must run in the SAME shell (it waits for the PID).
# Read only: -p, and never -I: recon keeps the interface. -l so no line sits in a buffer at a signal, -t so
# no clock time is printed. -s 1024: only the first 1024 bytes of a frame, radiotap header included, so Remote
# ID placed further in is not seen (Phase 0 on the Pager, 2026-10-02: no beacon heard there came near it, the
# largest 526 bytes, and a crafted 4 KB frame cut to 1024 costs the decoder about 8 times less). It ends by
# itself: timeout TERMs tcpdump after SW_RID_SECONDS (awk then reaches the end of its input and prints its
# lines), or -c stops it; an orphaned capture still ends within SW_RID_SECONDS + 2 s. Nothing here is ever
# found or stopped by name.
sw_rid_start() {
  SW_RID_PID=""; SW_RID_CAP=""; SW_RID_ERR=""
  [ "${SW_REMOTE_ID:-0}" = 1 ] || return 0
  command -v tcpdump >/dev/null 2>&1 || return 0
  sw_stopped && return 0
  local now="$1" secs="${SW_RID_SECONDS:-12}" maxf="${SW_RID_MAX_FRAMES:-300}" maxd="${SW_RID_MAX_DRONES:-32}" cap err keys
  [[ "$secs" =~ ^[1-9][0-9]{0,4}$ ]] || secs=12
  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=300
  [[ "$maxd" =~ ^(0|[1-9][0-9]{0,3})$ ]] || maxd=32
  cap="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_rid.XXXXXX")" || { sw_rid_health_note capture_failed "$now"; return 0; }
  err="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_rid.XXXXXX")" || { rm -f "$cap"; sw_rid_health_note capture_failed "$now"; return 0; }
  _sw_rid_keys; keys="$REPLY"     # the drones the ignore list may silence are chosen last (the decoder's emit)
  _sw_rid_filter
  nice -n 10 timeout -k 2 "$secs" tcpdump -i "${SW_RID_IFACE:-wlan1mon}" -p -l -t -nn -xx -s 1024 -c "$maxf" "$REPLY" 2>"$err" \
    | nice -n 10 awk -v max="$maxd" -v ignkeys="$keys" "$(_sw_rid_awk_src)" > "$cap" 2>/dev/null &
  SW_RID_PID=$!; SW_RID_CAP="$cap"; SW_RID_ERR="$err"
}

# $1 = the lap's start (epoch), $2 = the loot dir. Waits for this lap's capture, notes its health, prints
# its drones as finished detections (like an evil twin, they skip the matcher) and removes its files.
sw_rid_collect() {
  local now="$1" loot="$2" pid="${SW_RID_PID:-}" cap="${SW_RID_CAP:-}" err="${SW_RID_ERR:-}"
  SW_RID_PID=""; SW_RID_CAP=""; SW_RID_ERR=""
  [ -n "$pid" ] || return 0
  wait "$pid" 2>/dev/null
  # stopped during the window: drop the capture unread and report nothing (a relaunch owns the screen now)
  if sw_stopped; then rm -f "$cap" "$err"; return 0; fi
  local l started=0 radio=0 pkts="" drops="" stats=0 frames=0 understood=0 more=0 tag ridf maxf="${SW_RID_MAX_FRAMES:-300}" st
  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=300
  while IFS= read -r l || [ -n "$l" ]; do
    case "$l" in
      "listening on "*) started=1; case "$l" in *"link-type IEEE802_11_RADIO "*) radio=1 ;; esac ;;
      [0-9]*" packet captured"|[0-9]*" packets captured") pkts="${l%% *}" ;;   # "1 packet", "N packets"
      [0-9]*" packet dropped by kernel"|[0-9]*" packets dropped by kernel") drops="${l%% *}" ;;
    esac
  done < "$err"
  # the decoder prints its stats line last, after its drone lines: without one it did not finish
  while IFS= read -r l || [ -n "$l" ]; do
    case "$l" in S$'\t'*) stats=1; IFS='|' read -r tag frames understood ridf more <<< "${l//$'\t'/|}" ;; esac
  done < "$cap"
  [[ "$frames" =~ ^[0-9]{1,9}$ ]] || frames=0; [[ "$understood" =~ ^[0-9]{1,9}$ ]] || understood=0
  [[ "$more" =~ ^[0-9]{1,9}$ ]] || more=0; [[ "$pkts" =~ ^[0-9]{1,9}$ ]] || pkts=""
  [[ "$drops" =~ ^[0-9]{1,9}$ ]] || drops=0
  # OFF first (nothing usable), then the two ways of being partly blind
  if [ "$started" -ne 1 ]; then st=capture_failed
  elif [ "$radio" -ne 1 ]; then st=not_understood                                   # not 802.11 + radiotap
  elif [ "$stats" -ne 1 ]; then st=not_understood                                   # the decoder did not finish
  elif [ "$frames" -ge 5 ] && [ "$understood" -eq 0 ]; then st=not_understood       # the format changed
  elif [ -n "$pkts" ] && [ "$pkts" -ge "$maxf" ]; then st=capped                    # the frame cap (a flood?)
  elif [ -n "$pkts" ] && [ "$frames" -lt "$pkts" ]; then st=lost                    # frames lost on the way
  elif [ "$drops" -gt 0 ]; then st=lost                                             # the kernel dropped some
  else st=ok; fi                                                                    # a lap with no frames too
  sw_rid_health_note "$st" "$now"
  # An OFF status never comes with drones: bytes under another link type are not 802.11 frames, and a decoder
  # that did not finish is not trusted. A partly blind capture reports what it heard.
  case "$st" in
    capture_failed|not_understood) ;;
    *) sw_rid_records "$now" "$loot" < "$cap"
       [ "$more" -gt 0 ] && _sw_rid_say magenta "...and $more more drones (Remote ID flood?)" ;;
  esac
  rm -f "$cap" "$err"
}

#!/bin/bash
# lib/remoteid.sh — Remote ID over WiFi (spec docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md).
# Drones broadcast Remote ID (their ID, position and the pilot's location) in WiFi beacons and in NAN
# action frames. Each lap a short, read-only tcpdump window on the recon radio feeds ONE awk pass, which
# decodes those frames into one line per transmitter address, written as integers, empty fields or
# lowercase hex only: Remote ID is not authenticated, so no broadcast byte may shift a field. Bash then
# does the units, the cleaning (sw_sanitize_ident), the remoteid.csv rows and the detections.

# --- The decoder: tcpdump -t -nn -xx text in; a stats line and one line per drone out (spec §6.2) ---
#   S<TAB>frames<TAB>understood<TAB>rid_frames<TAB>more_drones
#   D<TAB>mac rssi forms id_type id_hex id2_type id2_hex ua_type status lat lon alt_geo alt_baro height
#        height_ref speed vspeed heading pilot_type pilot_lat pilot_lon pilot_alt operator_id_hex self_id_hex
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
function txt(i, n,  r, c, j) { r = ""
  for (j = 0; j < n && i + j < nb(); j++) { c = b(i + j); if (c == 0) break; r = r sprintf("%02x", c) }
  while (length(r) >= 2 && substr(r, length(r) - 1) == "20") r = substr(r, 1, length(r) - 2)
  return r }
function hexall(i, n,  r, j) { r = ""; for (j = 0; j < n; j++) r = r sprintf("%02x", b(i + j)); return r }
# both 0 is the standard's "unknown"; out of range is garbage
function okll(a, o) { return !(a == 0 && o == 0) && a >= -900000000 && a <= 900000000 && o >= -1800000000 && o <= 1800000000 }
function okpack(pk, end,  c) { if (pk + 3 > end) return 0
  if (int(b(pk) / 16) != 15 || b(pk + 1) != 25) return 0
  c = b(pk + 2); if (c < 1 || c > 9) return 0
  return pk + 3 + 25 * c <= end }
BEGIN { for (k = 0; k <= 9; k++) hx[k] = k; hx["a"] = 10; hx["b"] = 11; hx["c"] = 12; hx["d"] = 13; hx["e"] = 14; hx["f"] = 15 }
$1 !~ /^0x[0-9a-f]+:$/ { if (hex != "") decode(); hex = ""; sig = ""
  # tcpdump prints the radiotap fields before any frame text, so a network name cannot supply this
  if (match($0, /-?[0-9]+dBm signal/)) sig = substr($0, RSTART, RLENGTH - 10)
  next }
{ for (k = 2; k <= NF; k++) hex = hex $k }
END { if (hex != "") decode(); emit() }
function decode(  off, fc, hl, ie, id, ln, f, i, pk, steps) {
  frames++
  if (length(hex) % 2) return
  off = le16(2)                                              # the radiotap length = where 802.11 starts
  if (b(0) != 0 || off < 8 || off + 24 > nb()) return
  fc = b(off); fc = fc - fc % 4                              # frame control, version bits masked
  if (fc != 128 && fc != 208) return                         # beacon or action frame only
  hl = (b(off + 1) >= 128) ? 28 : 24                         # 4 more header bytes when the Order bit is set
  if (off + hl > nb()) return
  understood++
  # cheap pre-test: only a frame holding ASD-STAN FA0BBC0D, the Parrot OUI or the NAN service id hash gets the walk
  if (!index(hex, "fa0bbc0d") && !index(hex, "903ae6") && !index(hex, "8869199d9209")) return
  if (fc == 128) { ie = off + hl + 12                        # beacon: walk its elements
    while (ie + 2 <= nb() && steps++ < 64) { id = b(ie); ln = b(ie + 1)   # at most 64 elements per frame
      if (ie + 2 + ln > nb()) break                          # one running past the end ends the walk
      if (id == 221 && ln >= 8) { f = 0
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
  while (i + 3 <= nb() && steps++ < 64) { ln = le16(i + 1)   # at most 64 attributes per frame
    if (i + 3 + ln > nb()) break
    if (b(i) == 3 && ln >= 9 && b(i + 3) == 136 && b(i + 4) == 105 && b(i + 5) == 25 && b(i + 6) == 157 && b(i + 7) == 146 && b(i + 8) == 9) {
      pk = nanpack(i + 9, i + 3 + ln)                        # just after the service id hash
      if (pk && okpack(pk, sie)) { take(off + 10, pk, 2); return } }
    i = i + 3 + ln }
}
# after the service id: instance, requestor, control, the optional fields control announces, then
# the service info (length, counter, pack). Returns the pack's offset (0 = none); sie = its end.
function nanpack(p, end,  c) { if (p + 3 > end) return 0
  c = b(p + 2); p = p + 3
  if (bit(c, 64)) p = p + 2                                  # binding bitmap
  if (bit(c, 4)) { if (p >= end) return 0; p = p + 1 + b(p) } # matching filter
  if (bit(c, 8)) { if (p >= end) return 0; p = p + 1 + b(p) } # service response filter
  if (!bit(c, 16) || p + 2 > end) return 0                   # service info present?
  sie = p + 1 + b(p); if (sie > end) return 0
  return p + 2 }
function take(a, pk, f,  m, c, n, i, t, v, w) { m = hexall(a, 6)
  if (!(m in seen)) { seen[m] = 1; ord[++no] = m }
  if (sig != "" && (!(m in rs) || sig + 0 > rs[m] + 0)) rs[m] = sig
  if (!bit(fm[m] + 0, f)) fm[m] = fm[m] + f
  ridf++
  c = b(pk + 2)
  for (n = 0; n < c; n++) { i = pk + 3 + 25 * n; t = int(b(i) / 16)
    if (t == 0) { v = txt(i + 2, 20)                         # Basic ID: the first two distinct ones
      if (nbi[m] + 0 == 0) { it1[m] = int(b(i + 1) / 16); ih1[m] = v; ua[m] = b(i + 1) % 16; nbi[m] = 1 }
      else if (nbi[m] == 1 && (v != ih1[m] || int(b(i + 1) / 16) != it1[m])) { it2[m] = int(b(i + 1) / 16); ih2[m] = v; nbi[m] = 2 } }
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
  print "D\t" m "\t" rs[m] "\t" (fm[m] + 0) "\t" it1[m] "\t" ih1[m] "\t" it2[m] "\t" ih2[m] "\t" ua[m] "\t" st[m] \
    "\t" la[m] "\t" lo[m] "\t" ag[m] "\t" ab[m] "\t" ht[m] "\t" hr[m] "\t" sp[m] "\t" vs[m] "\t" hd[m] \
    "\t" pt[m] "\t" pa[m] "\t" po[m] "\t" pl[m] "\t" oi[m] "\t" si[m] }
# the strongest signals first, at most max of them (0 = no cap); a missing signal counts as weakest
function emit(  k, j, best, bv, v, kept) { kept = 0
  if (max + 0 == 0) { for (k = 1; k <= no; k++) line(ord[k]); kept = no }
  else for (k = 1; k <= no && kept < max + 0; k++) { best = 0
    for (j = 1; j <= no; j++) { if (used[j]) continue
      v = (ord[j] in rs) ? rs[ord[j]] + 0 : -999
      if (!best || v > bv) { best = j; bv = v } }
    used[best] = 1; kept++; line(ord[best]) }
  print "S\t" frames + 0 "\t" understood + 0 "\t" ridf + 0 "\t" no - kept }
RIDAWK
}
# stdin = tcpdump -t -nn -xx text -> the lines above; at most SW_RID_MAX_DRONES D lines (0 = no cap)
_sw_rid_decode_awk() { awk -v max="${SW_RID_MAX_DRONES:-32}" "$(_sw_rid_awk_src)"; }


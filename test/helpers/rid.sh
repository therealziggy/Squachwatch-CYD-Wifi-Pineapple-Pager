# test/helpers/rid.sh — sourced by tests (NOT by run.sh, which sources only *_test.sh).
# sw_test_rid_line KEY=VALUE... prints one decoder "D" line (the 24 fields in lib/remoteid.sh's order),
# so the bash layer can be tested without the decoder. A key not given takes the full test drone's value
# (the same values as tools/rid_fixtures/gen.c's beacon); "key=" makes that field empty. forms is a bit mask:
# 1 beacon, 2 NAN, 4 Parrot, and 8 when the address sent more distinct IDs than the two kept (e.g. forms=9).
sw_test_rid_line() {
  local -A f=(); local kv
  for kv in "$@"; do f[${kv%%=*}]="${kv#*=}"; done
  printf 'D\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${f[mac]-80e126aabbcc}" "${f[rssi]--47}" "${f[forms]-1}" "${f[id_type]-1}" \
    "${f[id_hex]-3030303046535754455354303030303030303031}" "${f[id2_type]-}" "${f[id2_hex]-}" \
    "${f[ua_type]-2}" "${f[status]-2}" "${f[lat]-473977600}" "${f[lon]-85454200}" \
    "${f[alt_geo]-3040}" "${f[alt_baro]-}" "${f[height]-2174}" "${f[height_ref]-0}" \
    "${f[speed]-1200}" "${f[vspeed]-30}" "${f[heading]-215}" "${f[pilot_type]-1}" \
    "${f[pilot_lat]-473980000}" "${f[pilot_lon]-85410200}" "${f[pilot_alt]-}" \
    "${f[operator_id]-5357544553544f50455241544f523031}" "${f[self_id]-}"
}
# sw_test_rid_at FILE MAC SIGNAL prints the frame in FILE, a fixture laid out as the reference beacon (from
# 80:e1:26:aa:bb:cc at -47 dBm, a 9-byte radiotap header), as heard from address MAC (12 lowercase hex digits) at
# SIGNAL dBm: a TEXT edit of the committed fixture, of the header line's "-47dBm signal", the radiotap signal
# byte (0x08) and addr2 (0x13-0x18). A fixture it cannot edit that way is an error (rc 1), never printed as it is.
sw_test_rid_at() {
  local m="$2" t=$'\t' s out
  printf -v s %02x $(( $3 & 255 ))
  out="$(sed -e "s/^-47dBm signal /$3dBm signal /" \
             -e "s/^\(${t}0x0000:  0000 0900 2000 0000 \)d1/\1$s/" \
             -e "s/^\(${t}0x0010:  ffff ff\)80 e126 aabb cc/\1${m:0:2} ${m:2:4} ${m:6:4} ${m:10:2}/" "$1")"
  case "$out" in
    "$3dBm signal "*"${t}0x0000:  0000 0900 2000 0000 $s"*"${t}0x0010:  ffff ff${m:0:2} ${m:2:4} ${m:6:4} ${m:10:2}"*)
      printf '%s\n' "$out" ;;
    *) echo "sw_test_rid_at: $1 is not laid out as the reference beacon" >&2; return 1 ;;
  esac
}
# sw_test_rid_id FILE HEX prints the frame in FILE, laid out as the reference beacon, with its first Basic ID's
# 20 bytes (0x48-0x5b) made HEX (lowercase, whole bytes, at most 20), zero-filled: a TEXT edit of the committed
# fixture. Other HEX, or a fixture it cannot edit that way, is an error (rc 1).
sw_test_rid_id() {
  local h="$2" t=$'\t' g out
  case "$h" in *[!0-9a-f]*) echo "sw_test_rid_id: HEX is lowercase hex digits" >&2; return 1 ;; esac
  if [ $(( ${#h} % 2 )) -ne 0 ] || [ "${#h}" -gt 40 ]; then echo "sw_test_rid_id: HEX is whole bytes, at most 20" >&2; return 1; fi
  while [ "${#h}" -lt 40 ]; do h+=0; done
  g=("${h:0:4}" "${h:4:4}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:4}" "${h:24:4}" "${h:28:4}" "${h:32:4}" "${h:36:4}")
  out="$(sed -e "s/^\(${t}0x0040:  bc0d 00f2 1904 02[0-9a-f][0-9a-f]\) [0-9a-f]\{4\} [0-9a-f]\{4\} [0-9a-f]\{4\} [0-9a-f]\{4\}\$/\1 ${g[0]} ${g[1]} ${g[2]} ${g[3]}/" \
             -e "s/^${t}0x0050:  [0-9a-f]\{4\} [0-9a-f]\{4\} [0-9a-f]\{4\} [0-9a-f]\{4\} [0-9a-f]\{4\} [0-9a-f]\{4\}\( 0000 0012\)\$/${t}0x0050:  ${g[4]} ${g[5]} ${g[6]} ${g[7]} ${g[8]} ${g[9]}\1/" "$1")"
  case "$out" in
    *"${t}0x0040:  bc0d 00f2 1904 02"??" ${g[0]} ${g[1]} ${g[2]} ${g[3]}"*"${t}0x0050:  ${g[4]} ${g[5]} ${g[6]} ${g[7]} ${g[8]} ${g[9]} 0000 0012"*)
      printf '%s\n' "$out" ;;
    *) echo "sw_test_rid_id: $1 is not laid out as the reference beacon" >&2; return 1 ;;
  esac
}

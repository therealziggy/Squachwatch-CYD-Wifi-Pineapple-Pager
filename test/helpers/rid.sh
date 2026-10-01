# test/helpers/rid.sh — sourced by tests (NOT by run.sh, which sources only *_test.sh).
# sw_test_rid_line KEY=VALUE... prints one decoder "D" line (the 24 fields in lib/remoteid.sh's order),
# so the bash layer can be tested without the decoder. A key not given takes the full test drone's value
# (the same values as tools/rid_fixtures/gen.c's beacon); "key=" makes that field empty.
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

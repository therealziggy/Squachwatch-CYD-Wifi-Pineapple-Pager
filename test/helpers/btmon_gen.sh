# test/helpers/btmon_gen.sh — sourced by tests (NOT by run.sh, which sources only *_test.sh).
# sw_test_btmon_devs PREFIX COUNT NAME RSSI -> btmon 5.72-shaped text: COUNT advertising
# reports from PREFIX:01 .. PREFIX:<COUNT in hex>, each with the given complete name and RSSI.
# The layout follows test/fixtures/btmon_synthetic.txt, which was copied from a real capture.
sw_test_btmon_devs() {
  local prefix="$1" count="$2" name="$3" rssi="$4" i
  for (( i = 1; i <= count; i++ )); do
    printf '> HCI Event: LE Meta Event (0x3e) plen 30                    #%d [hci0] 1.%06d\n' "$i" "$i"
    printf '      LE Advertising Report (0x02)\n'
    printf '        Num reports: 1\n'
    printf '        Address type: Random (0x01)\n'
    printf '        Address: %s:%02X (Static)\n' "$prefix" "$i"
    printf '        Name (complete): %s\n' "$name"
    printf '        RSSI: %s dBm (0xc4)\n' "$rssi"
  done
}

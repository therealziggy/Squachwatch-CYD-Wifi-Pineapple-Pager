#!/bin/bash
# p0-verify.sh — run ON THE PAGER. Prints a labeled report confirming the
# assumptions SquachWatch-Pager's engine depends on. Discovery, not TDD:
# each probe has an expected positive result; record negatives as blockers.
line(){ echo "==== $* ===="; }

line "recon.db present + schema"
ls -l /root/recon/recon.db 2>&1
cp /root/recon/recon.db /tmp/p0.db 2>&1 && echo "copy_ok"
sqlite3 /tmp/p0.db ".tables" 2>&1
sqlite3 /tmp/p0.db "SELECT count(*) AS beacons FROM ssid WHERE type=8;" 2>&1
sqlite3 /tmp/p0.db "SELECT count(*) AS clients FROM ssid WHERE type=4;" 2>&1
sqlite3 /tmp/p0.db "PRAGMA table_info(ssid);" 2>&1
sqlite3 /tmp/p0.db "PRAGMA table_info(wifi_device);" 2>&1

line "_pineap RECON APS json (alt enumeration)"
_pineap RECON APS format=json 2>&1 | head -c 400; echo

line "sqlite3 / jq presence"
which sqlite3 jq 2>&1

line "BLE tooling"
which hcitool bluetoothctl btmon 2>&1
hciconfig -a 2>&1 | head -20
timeout 6 hcitool lescan --duplicates 2>&1 | head -5

line "raw-adv capability (Tier-3 gate)"
which btmon 2>&1 && echo "btmon_present" || echo "btmon_absent"
timeout 4 btmon 2>&1 | head -5

line "DuckyScript verbs on PATH"
for c in ALERT LOG RINGTONE VIBRATE LED GPS_GET TITLE START_SPINNER STOP_SPINNER PAYLOAD_GET_CONFIG PAYLOAD_SET_CONFIG; do
  printf '%s: ' "$c"; command -v "$c" 2>/dev/null || echo MISSING
done

line "LED syntax probe (observe device reaction)"
LED B 50 2>&1; sleep 1; LED OFF 2>&1; echo "led_probe_done"

line "OUI vendor DB format (client vendor lookup depends on this)"
ls -l /lib/hak5/oui.txt /rom/lib/hak5/oui.txt 2>&1 | head
head -3 /lib/hak5/oui.txt 2>/dev/null | cat -A

line "sysfs hardware paths (fallback)"
ls /sys/class/leds/ 2>&1
ls -l /sys/class/gpio/vibrator/value 2>&1
ls /sys/class/vtconsole/ 2>&1

line "bash version + interfaces + space"
bash --version | head -1
iw dev 2>&1 | grep Interface
df -h /root 2>&1 | tail -1

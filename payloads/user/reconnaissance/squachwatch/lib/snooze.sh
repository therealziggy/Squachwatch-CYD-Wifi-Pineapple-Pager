#!/bin/bash
# lib/snooze.sh — AUTO SNOOZE for repeat full-screen alerts, ported from SquachWatch-CYD
# (include/detection.h, DetectionEngine::alertGate).
#
# A device gets AFTER full-screen alerts for free. After that it may interrupt again only by
# coming CLOSER than it ever has: its RSSI must beat the strongest it ever alerted at by
# MARGIN dB, because RSSI wobbles about 5 dB between samples with nothing moving. Its
# allowance comes back once it has been gone for RESET seconds. Only the full-screen alert
# and buzz are gated: the caller keeps writing the CSV row and log line.
#
# One deliberate deviation: CYD resets the allowance on time since the last ALERT. Its own
# comment states the intent as "how long a device has to be gone", and for a tracker that
# stays with you the literal rule would re-arm a burst every RESET seconds. So this resets on
# time since the device was last SEEN here, i.e. since the last consultation.
#
# State: one line per key, "mac|category|alerts|bar|last_seen"; bar is empty until an alert
# carries a known RSSI. It runs once per would-be alert (rare), not per record, so it may fork.

sw_snooze_gate() {
  # $1=mac $2=category $3=rssi (dBm, may be empty) $4=now $5=statefile
  # $6=after (0 = feature off) $7=margin_db $8=reset_secs
  # rc 0 = interrupt; 2 = interrupt, and that was its last free alert; 1 = hold.
  local mac="$1" cat="$2" rssi="$3" now="$4" sf="$5" after="$6" margin="$7" reset="$8"
  case "$after" in ''|*[!0-9]*|0) return 0 ;; esac
  local key="$mac|$cat" alerts=0 bar="" seen=0 line r tmp rc num='^-?[0-9]+$'
  if [ -f "$sf" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [ "${line%|*|*|*}" = "$key" ] || continue
      seen="${line##*|}"; r="${line%|*}"; bar="${r##*|}"; r="${r%|*}"; alerts="${r##*|}"
    done < "$sf"
  fi
  # Gone longer than the reset window: a clean slate.
  if [ "$seen" -gt 0 ] && [ $((now - seen)) -gt "$reset" ]; then alerts=0; bar=""; fi
  if [ "$alerts" -lt "$after" ]; then
    alerts=$((alerts + 1))
    # The bar is the strongest it has EVER interrupted at, not the last one.
    if [[ "$rssi" =~ $num ]] && { [ -z "$bar" ] || [ "$rssi" -gt "$bar" ]; }; then bar="$rssi"; fi
    if [ "$alerts" -eq "$after" ]; then rc=2; else rc=0; fi
  elif [[ "$rssi" =~ $num ]] && [[ "$bar" =~ $num ]] && [ "$rssi" -ge $((bar + margin)) ]; then
    bar="$rssi"; rc=0              # came closer than ever, by more than RSSI noise
  else
    rc=1
  fi
  # Rewrite via a temp file + mv, dropping entries gone longer than the reset window. If the
  # state can't be written, the answer still stands; the next call just starts fresh. That
  # errs toward MORE alerts, never toward silence.
  if tmp="$(mktemp "$sf.XXXXXX" 2>/dev/null)"; then
    if [ -f "$sf" ]; then
      while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        [ "${line%|*|*|*}" = "$key" ] && continue
        [ $((now - ${line##*|})) -le "$reset" ] && printf '%s\n' "$line" >> "$tmp"
      done < "$sf"
    fi
    printf '%s|%s|%s|%s\n' "$key" "$alerts" "$bar" "$now" >> "$tmp"
    mv -f "$tmp" "$sf" 2>/dev/null || rm -f "$tmp"
  fi
  return $rc
}

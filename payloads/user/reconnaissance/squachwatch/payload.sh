#!/bin/bash
# Title: SquachWatch
# Description: Always-on detector for surveillance devices, trackers, and hacker tools.
# Author: ziggy
# Version: 1.0
# Category: reconnaissance
# Homage to SquachWatch-CYD (skizzophrenic); reuses Hak5 community payload patterns.

# A Stop while the libs and signatures load (about a quarter of a second on the Pager) must end
# the run cleanly too. Nothing has been started or written yet, so a plain exit is all it needs;
# sw_main replaces this with the full trap as its first step. Skipped when a test sources this
# file, so the test shell's own signal handling stays as it was.
[ -n "${SW_TEST_SOURCE:-}" ] || trap 'exit 0' INT TERM

# The Pager UI does not run this file in place: it runs a copy (/tmp/payload-<n>.sh) and
# passes the real folder in PAYLOAD_HOME. BASH_SOURCE is only right for a direct
# `bash payload.sh` (SSH, tests).
SW_HOME="${PAYLOAD_HOME:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )}"
SW_HOME="${SW_HOME%/}"
# Without its libs every lap is a silent no-op (each step is "command not found"), so a
# lib that won't load stops the payload loudly instead of letting it run blind.
for l in match wifi ble alert log follow ignore snooze eviltwin remoteid; do
  . "$SW_HOME/lib/$l.sh" || { LOG red "ERROR: can't load $SW_HOME/lib/$l.sh — SquachWatch NOT running" 2>/dev/null; exit 1; }
done

# --- config (overridable via env / PAYLOAD_GET_CONFIG on device) ---
: "${SW_RECON_DB:=/root/recon/recon.db}"
: "${SW_BLE_IFACE:=hci0}"
: "${SW_BLE_SECONDS:=12}"
: "${SW_COOLDOWN:=600}"
: "${SW_LOOT_DIR:=/root/loot/squachwatch}"
: "${SW_SEEN_FILE:=$SW_LOOT_DIR/seen.db}"
: "${SW_SLEEP:=3}"
# Only match devices seen in the last N seconds. recon.db keeps months of history
# (20,294 rows on a real Pager, 222 of them from the last 10 min) and a proximity
# detector only cares about what is nearby now. 0 scans the whole DB.
: "${SW_RECENCY_SECS:=600}"
# Re-run the health check every N laps so a recon DB that dies mid-run still gets
# reported instead of quietly turning the sweep into "all clear".
: "${SW_HEALTH_EVERY:=20}"

# Tier-3 follow detection: a tracker seen continuously for SW_FOLLOW_SECS escalates from a
# logged presence to a full alert; a gap longer than SW_FOLLOW_GAP restarts its clock.
: "${SW_FOLLOW_SECS:=900}"
: "${SW_FOLLOW_GAP:=300}"
# The follow timer ignores tracker sightings weaker than this (dBm): a tracker on you or in your
# car reads far stronger, and a neighbour's heard through a wall (-95 on 2026-09-23) must not
# "follow" you at home. The tracker is still logged. It must be a negative number without a
# leading zero, e.g. -85; -085, 0, 85, or empty all turn the floor off. No ":=": that would
# replace an explicitly EMPTY value with the default too, so "empty turns it off" would
# silently stop working (I6).
: "${SW_FOLLOW_MIN_RSSI=-85}"
# Follow state is rewritten on every lap for every tracker, so it lives in RAM (/tmp), not on
# flash: no flash wear, faster writes. A reboot just restarts the follow clock.
: "${SW_TRACK_FILE:=${SW_TMP_DIR:-/tmp}/sw_track.db}"
# The owner's own devices, one MAC per line. Lives in the loot dir so redeploys keep it.
: "${SW_IGNORE_FILE:=$SW_LOOT_DIR/ignore.txt}"
# AUTO SNOOZE for "following you" alerts, ported from SquachWatch-CYD: a follower gets
# SW_SNOOZE_AFTER full alerts, then re-alerts only if it comes SW_SNOOZE_MARGIN_DB closer than
# its strongest alert, or after it has been gone SW_SNOOZE_RESET_SECS. Its CSV rows and log
# lines continue throughout. 0 turns it off. State is in RAM, like the follow state.
: "${SW_SNOOZE_AFTER:=3}"
: "${SW_SNOOZE_MARGIN_DB:=7}"
: "${SW_SNOOZE_RESET_SECS:=1800}"
: "${SW_SNOOZE_FILE:=${SW_TMP_DIR:-/tmp}/sw_snooze.db}"
# One full alert + buzz per KIND of device (category) per window, but only for HIGH-confidence
# detections: a name-only BLE Spam flood is med confidence and never alerts at all (0 times, not
# once); a flood of HARDWARE-matched devices of one kind (a hacker con full of real Flippers, or
# several Flock cameras) interrupts once. Every device still gets its CSV row, and a screen line
# up to the per-lap cap (SW_LOG_PER_KIND below). "Following you" alerts are exempt. 0 turns it off.
: "${SW_KIND_COOLDOWN:=600}"
# Per lap, at most this many screen lines per kind AND CONFIDENCE LEVEL of device (final review
# 2: a real high-confidence device gets its own allowance, separate from a same-kind med/low
# flood), then one "...and N more <label>" line, so a flood cannot scroll everything else off
# the screen. The CSV keeps every row. 0 = no cap.
: "${SW_LOG_PER_KIND:=3}"
# Evil-twin check (spec 2026-09-29): a network name offered both open and password-protected within
# the recency window (600 s when that window is off) reports each open copy as an evil twin, with a
# full alert like any other high-confidence find. 1 = on; anything else turns it off.
: "${SW_EVIL_TWIN:=1}"
# Remote ID over WiFi (spec 2026-10-01): each lap a short, read-only tcpdump window on the recon radio
# decodes the Remote ID that drones broadcast (their ID, position, height, speed and the pilot's
# location) into a full alert, plus a row per lap in remoteid.csv. 1 = on; anything else turns it off.
: "${SW_REMOTE_ID:=1}"
# The radio it listens on: the recon radio, whose channel hopping it rides (it never retunes it).
: "${SW_RID_IFACE:=wlan1mon}"
# The capture window in seconds. It starts with the lap and the lap waits for it, so a window longer than the
# BLE scan (about 13 s) makes every lap longer.
: "${SW_RID_SECONDS:=12}"
# At most this many frames per lap (it reads every nearby beacon, so a beacon flood must not eat the
# CPU), and this many drones per lap (the strongest; the rest are counted on one line; 0 = no cap, in the
# order heard, which lets a flood of made-up drones cost each lap time and two CSV rows per drone).
: "${SW_RID_MAX_FRAMES:=1500}"
: "${SW_RID_MAX_DRONES:=32}"
# The flight-track log: one row per drone per lap in which it was heard.
: "${SW_RID_FILE:=$SW_LOOT_DIR/remoteid.csv}"

SW_SIGS="$(sw_load_signatures "$SW_HOME/signatures.db")"
SW_IGNORE_SET="$(sw_load_ignore "$SW_IGNORE_FILE")"

# A health WARN, unless the payload has been stopped. sw_main runs the check in the background,
# so a Stop can leave it running on its own, and what it finds then is wrong: the exit trap has
# removed its recon DB copy, so a healthy DB reads as "not updating". Its lines would also land
# on the next payload's screen.
_sw_health_warn() { sw_stopped || LOG yellow "$1" 2>/dev/null; }

# One-shot health signal. A silently dead source (missing sqlite3, unreadable recon DB,
# or empty signatures) must NOT read as "all clear" — warn loudly. Returns nonzero if degraded.
sw_healthcheck() {
  local degraded=0
  if ! command -v sqlite3 >/dev/null 2>&1; then
    _sw_health_warn "WARN: sqlite3 missing — WiFi detection OFF (opkg install sqlite3-cli)"; degraded=1
  elif [ ! -r "$SW_RECON_DB" ]; then
    _sw_health_warn "WARN: recon DB unreadable ($SW_RECON_DB) — WiFi detection OFF"; degraded=1
  fi
  if [ -z "$SW_SIGS" ]; then
    _sw_health_warn "WARN: no signatures loaded — nothing will match"; degraded=1
  fi
  # A DB full of rows with none inside the recency window means recon stopped writing
  # (or the clock is wrong): every sweep would return zero and look like "all clear".
  if sw_wifi_stale_db "$SW_RECON_DB"; then
    _sw_health_warn "WARN: recon DB not updating (no rows in last ${SW_RECENCY_SECS}s) — WiFi detection is blind"; degraded=1
  fi
  # btmon is the only BLE data source (Tier-3): without it every BLE lap is empty.
  if ! command -v btmon >/dev/null 2>&1; then
    _sw_health_warn "WARN: btmon missing — BLE detection OFF"; degraded=1
  fi
  # Remote ID over WiFi (spec 2026-10-01 §7.1) captures with tcpdump on the recon radio: without either,
  # no capture ever starts. (Recon itself stopping is the stale-DB WARN above.) SW_SYSFS_NET is a test seam.
  if [ "${SW_REMOTE_ID:-0}" = 1 ]; then
    if ! command -v tcpdump >/dev/null 2>&1; then
      _sw_health_warn "WARN: tcpdump missing — Remote ID over WiFi OFF"; degraded=1
    elif [ ! -e "${SW_SYSFS_NET:-/sys/class/net}/${SW_RID_IFACE:-wlan1mon}" ]; then
      _sw_health_warn "WARN: ${SW_RID_IFACE:-wlan1mon} missing — Remote ID over WiFi OFF"; degraded=1
    fi
  fi
  # Every WiFi check reads a copy of the recon DB in ${SW_TMP_DIR:-/tmp}. When no copy can be made
  # (a full /tmp, say) the WiFi sweep and the evil-twin check skip every lap, so that is a WARN. On
  # the copy runs the evil-twin check's own probe: a DB that stops recording what the check needs (a
  # firmware update, say) would leave it finding nothing, forever, and reading as "all clear" (spec
  # 2026-09-29 §7). Only when the DB itself is usable (the WARNs above cover the rest), and never
  # once stopped: a check left running by a Stop makes no new DB copy.
  if command -v sqlite3 >/dev/null 2>&1 && [ -r "$SW_RECON_DB" ] && ! sw_stopped; then
    if sw_recon_snapshot "$SW_RECON_DB" 2>/dev/null; then
      local copy="$REPLY" st=1
      if [ "${SW_EVIL_TWIN:-0}" = 1 ]; then
        sw_evil_twin_blind "$copy"; st=$?
        # A damaged copy is usually one torn by a write in progress: look at one fresh copy before
        # saying anything. A DB that is damaged for good reads that way twice.
        if [ "$st" -eq 2 ] && ! sw_stopped; then
          sw_recon_drop "$copy"; copy=""; st=1
          if sw_recon_snapshot "$SW_RECON_DB" 2>/dev/null; then copy="$REPLY"; sw_evil_twin_blind "$copy"; st=$?; fi
        fi
      fi
      case "$st" in
        0) _sw_health_warn "WARN: evil-twin check is blind (the recon DB no longer records what it needs)"; degraded=1 ;;
        2) _sw_health_warn "WARN: recon DB copy unreadable twice (damaged?) — WiFi detection OFF"; degraded=1 ;;
      esac
      [ -n "$copy" ] && sw_recon_drop "$copy"
    else
      _sw_health_warn "WARN: can't copy the recon DB to ${SW_TMP_DIR:-/tmp} (full?) — WiFi detection OFF"; degraded=1
    fi
  fi
  return $degraded
}

# BLE source seam: tests set SW_BLE_CMD; device uses real scan.
_sw_ble_records() {
  if [ -n "${SW_BLE_CMD:-}" ]; then eval "$SW_BLE_CMD" | sw_btmon_parse
  else sw_ble_scan "$SW_BLE_SECONDS" "$SW_BLE_IFACE"; fi
}

# Emit one detection under the lap's screen cap (spec 2026-09-23 §5). Called ONLY from
# sw_scan_once's lap loop: it updates that loop's per-lap arrays (bash dynamic scope).
# Counters are keyed by CATEGORY AND CONFIDENCE ("<cat>|<conf>"), not category alone (I1): a
# real high-confidence device gets its own allowance and its own "...and N more" line, so it
# can never be folded behind an unrelated med/low flood of the same category (e.g. a real
# Flipper behind a BLE-Spam name-only flood), and vice versa.
_sw_emit_capped() {
  local c="${1%%|*}" r="${1#*|}" lab conf tc cap="${SW_LOG_PER_KIND:-0}" key
  lab="${r%%|*}"; r="${r#*|}"
  conf="${r%%|*}"; r="${r#*|}"
  tc="${r%%|*}"
  key="$c|$conf"
  case "$cap" in ''|*[!0-9]*) cap=0 ;; esac
  if [ -z "${_lap_shown[$key]+x}" ]; then
    _lap_order+=("$key"); _lap_shown[$key]=0; _lap_hidden[$key]=0; _lap_label[$key]="$lab"; _lap_class[$key]="$tc"
  fi
  if [ "$cap" -gt 0 ] && [ "${_lap_shown[$key]}" -ge "$cap" ]; then
    _lap_hidden[$key]=$(( ${_lap_hidden[$key]} + 1 ))
    SW_EMIT_NOLOG=1 sw_emit "$@"
  else
    _lap_shown[$key]=$(( ${_lap_shown[$key]} + 1 ))
    sw_emit "$@"
  fi
}

sw_scan_once() {
  local now snap=""; now="$(date +%s)"
  # One recon DB copy per lap (6 MB on a real Pager), shared by the evil-twin check and the WiFi
  # signature sweep (spec 2026-09-29 §6.2). No copy (an unreadable DB, a full /tmp): both are
  # skipped this lap, and the health check says why.
  sw_recon_snapshot "$SW_RECON_DB" && snap="$REPLY"
  {
    # The Remote ID capture window opens first, so it spans the whole lap, and in THIS shell, which must
    # also be the one that collects it: it waits for the capture's PID (spec 2026-10-01 §6.1).
    sw_rid_start "$now"
    # Evil twins are finished detections, so they skip the matcher (spec 2026-09-29 §6.3). They
    # come first: the check is one query, and its alert need not wait for the BLE scan.
    [ -n "$snap" ] && [ "${SW_EVIL_TWIN:-0}" = 1 ] && sw_evil_twin_scan "$snap" "$now"
    # The copy goes as soon as the WiFi sweep has read it, before the BLE scan.
    { if [ -n "$snap" ]; then sw_wifi_records_in "$snap"; sw_recon_drop "$snap"; fi; _sw_ble_records; } \
      | sw_match_stream "$SW_SIGS"
    # Drones are finished detections too: collected once the BLE scan is over (spec 2026-10-01 §6.1)
    sw_rid_collect "$now" "$SW_LOOT_DIR"
  } | {
        # Per-lap screen counters (spec 2026-09-23 §5). They live in this pipeline subshell,
        # so they reset every lap.
        local -A _lap_shown=() _lap_hidden=() _lap_label=() _lap_class=()
        local -a _lap_order=()
        local det fdet key
        while IFS= read -r det; do
          [ -n "$det" ] || continue
          # the payload was stopped mid-lap: nothing more on screen, in the CSV, or buzzing
          sw_stopped && exit 0
          # A WiFi drone was checked against ignore.txt with every ID it sent, before its flight-track row
          # (lib/remoteid.sh): its line carries only the ID it shows, so it is not checked again here.
          case "$det" in "drone_rid|"*) ;; *) sw_ignored "$det" "$SW_IGNORE_SET" && continue ;; esac
          _sw_emit_capped "$det" "$now" "$SW_COOLDOWN" "$SW_SEEN_FILE" "$SW_LOOT_DIR"
          # a Stop that landed during that report: no follow escalation either
          sw_stopped && exit 0
          # A tracker that has stayed with us escalates to its own high-confidence detection.
          fdet="$(sw_follow_update "$det" "$now" "$SW_TRACK_FILE" "$SW_FOLLOW_SECS" "$SW_FOLLOW_GAP")"
          [ -n "$fdet" ] && _sw_emit_capped "$fdet" "$now" "$SW_COOLDOWN" "$SW_SEEN_FILE" "$SW_LOOT_DIR" \
            "$SW_SNOOZE_FILE" "$SW_SNOOZE_AFTER" "$SW_SNOOZE_MARGIN_DB" "$SW_SNOOZE_RESET_SECS"
        done
        sw_stopped && exit 0
        for key in "${_lap_order[@]}"; do
          [ "${_lap_hidden[$key]}" -gt 0 ] || continue
          LOG "$(sw_color_for "${_lap_class[$key]}")" "...and ${_lap_hidden[$key]} more ${_lap_label[$key]}" 2>/dev/null
        done
      }
  # normally removed already, right after the WiFi sweep; this covers a lap that ended early
  [ -n "$snap" ] && sw_recon_drop "$snap"
}

# The scanner's temp files: BLE captures (sw_ble.XXXXXX), the BLE health state (sw_ble.state), the
# Remote ID captures and their health state (sw_rid.XXXXXX, sw_rid.state) and the recon DB copies
# (sw_recon.XXXXXX, 5.6 MB each on a real Pager, and growing), all in RAM
# on the Pager; and the ledger prune's temp copy (seen.db.sw-prune-tmp.XXXXXX), in the loot dir on flash,
# where a leftover would outlive a reboot. Only sw_main runs this, before its own first prune.
sw_clear_tmp() { rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.* "${SW_TMP_DIR:-/tmp}"/sw_recon.* "${SW_TMP_DIR:-/tmp}"/sw_rid.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null; }

# On exit (the Pager's Stop, a Ctrl-C, a TERM): remove the BLE and Remote ID health states, any recon
# DB copy and the ledger prune's temp copy (only this shell prunes, and a Stop can land between the
# prune's mktemp and its mv), but leave BLE and Remote ID captures to the lap that owns them. A BLE lap
# still running reads its capture again for the health check, a Remote ID lap drops its capture unread,
# and each removes its capture itself on every path (sw_stopped); the next start sweeps whatever a lap
# could not. Nothing is killed here:
# btmon, hcitool and tcpdump each run under their own `timeout` (lib/ble.sh, lib/remoteid.sh), so an
# orphan ends within seconds by itself, while killing by NAME would also stop another program's
# btmon, hcitool or tcpdump (another payload, an SSH session).
sw_cleanup() {
  rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.state "${SW_TMP_DIR:-/tmp}"/sw_rid.state "${SW_TMP_DIR:-/tmp}"/sw_recon.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null
  exit 0
}

# Drop cooldown-ledger lines too old to block anything (spec 2026-09-23 §7), keeping the
# LONGER of the two windows that read the ledger. Called at startup and every SW_HEALTH_EVERY
# laps, so seen.db stays at "what was reported in the last window" instead of growing forever.
sw_prune_ledger() {
  local keep="$SW_COOLDOWN" k="${SW_KIND_COOLDOWN:-0}"
  case "$k" in ''|*[!0-9]*) k=0 ;; esac
  [ "$k" -gt "$keep" ] && keep="$k"
  sw_seen_prune "$SW_SEEN_FILE" "$(date +%s)" "$keep"
}

sw_main() {
  # sw_stopped's "main shell": always this one. An inherited value (a leftover export in an SSH
  # shell) would otherwise make every lap think the payload had been stopped.
  SW_MAIN_PID=$$
  # First, before this run creates anything: from here on a Stop must also clean up, so the full
  # trap replaces the plain exit the top of this file set. With no trap at all, bash drops a SIGINT
  # that lands during a foreground command (it takes the command's normal exit to mean the command
  # handled it) or, inside a command substitution, dies from it: never a clean exit.
  trap sw_cleanup EXIT INT TERM
  # Backstop for a run that ended without its trap (a crash, a power cut, a SIGKILL from
  # something else, a Stop while the libs were still loading): clear its leftovers here. A stale
  # capture or DB copy would stay in RAM, and a stale BLE health state would hide the WARN for
  # a scan that is still failing.
  sw_clear_tmp
  sw_log_init "$SW_LOOT_DIR"
  mkdir -p "$(dirname "$SW_SEEN_FILE")"; touch "$SW_SEEN_FILE"
  sw_prune_ledger
  sw_healthcheck &
  if wait $!; then
    LOG green "SquachWatch armed — watching WiFi + BLE" 2>/dev/null
  else
    LOG yellow "SquachWatch running DEGRADED — some detection is OFF (see warnings above)" 2>/dev/null
  fi
  local lap=0
  while true; do
    # The lap, the health check and the pause run in the background, under `wait`: the Pager's
    # Stop (SIGINT, then SIGKILL ~1 s later, to this shell only) then runs sw_cleanup at once.
    # Behind a foreground command the trap waited for that command, so the SIGKILL usually came
    # first. The step that was running winds down by itself without reporting anything (sw_stopped).
    # The ledger prune stays in the foreground: it is builtins apart from date, mktemp and mv (rm
    # and LOG on its failure paths), so the trap never waits more than milliseconds for it.
    sw_scan_once & wait $!
    lap=$((lap+1))
    if [ "$SW_HEALTH_EVERY" -gt 0 ] && [ $((lap % SW_HEALTH_EVERY)) -eq 0 ]; then
      sw_healthcheck &
      wait $! || LOG yellow "SquachWatch DEGRADED — some detection is OFF" 2>/dev/null
      sw_prune_ledger
    fi
    sleep "$SW_SLEEP" & wait $!
  done
}

# Auto-run unless sourced by a test.
[ -n "${SW_TEST_SOURCE:-}" ] || sw_main

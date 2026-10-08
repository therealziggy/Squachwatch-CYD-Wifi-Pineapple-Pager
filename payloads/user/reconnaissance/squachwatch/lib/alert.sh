#!/bin/bash
# lib/alert.sh — color map, cooldown dedupe, and (Task 9) emit.
sw_color_for() {
  case "$1" in
    surveillance) echo magenta ;;
    tracker)      echo yellow ;;
    attacker)     echo cyan ;;
    *)            echo white ;;
  esac
}

sw_should_report() {
  # $1=mac $2=category $3=now $4=cooldown_secs $5=seenfile
  # True (0) = this (device, category) is new or past its cooldown. Gates BOTH the
  # loot-CSV row and the full-screen alert, so it is named for reporting, not alerting.
  # Fails OPEN, never silent (spec 2026-09-23 §8): a stored timestamp can be wrong three ways --
  # a future timestamp after a backward clock step (the Pager has /dev/rtc0 plus ntpd, so this
  # is unlikely but possible), a torn line fused from two appends (e.g.
  # "AA:..|cat|<ts>BB:..|cat2|<ts2>"), where cut -d'|' -f3 lands on a non-integer fragment of
  # the SECOND line, or a LEADING ZERO (final review 2: e.g. "0800" or "09"), which bash
  # arithmetic reads as octal -- and neither is valid octal ("8"/"9" don't exist in base 8), so
  # $((now - last)) raised the same class of FATAL "value too great for base" error as a torn
  # line: proven by hand, a bash arithmetic error like this abandons the current top-level
  # command, not merely sw_should_report -- inside sw_scan_once's lap loop (its real call site)
  # that reaches no further than the rest of the caller's lap below, never the whole running
  # script (final review 3, T3; sw_seen_prune below is reached directly from sw_main with no
  # subshell in between, so its own top-level call site IS the one place the same class of
  # error really does end the payload -- spec §7).
  # Validate "last" with a plain-integer, NO-LEADING-ZERO check BEFORE
  # any arithmetic touches it: a bad or malformed value used to raise a bash arithmetic error
  # that ABORTED the rest of the caller's lap (devices lost their line and row, silently but for
  # stderr); now it is simply treated as fresh, the same as no entry at all, so the failure mode
  # is one extra alert, never a device (or, with a "*|category" key, a whole category) held
  # silent for as long as it takes the clock to catch up. The {0,11} length cap (bash `[[ =~ ]]`
  # is POSIX ERE, so this is portable) also keeps a stored value from overflowing bash's integer
  # arithmetic and raising the same class of error a different way.
  local mac="$1" cat="$2" now="$3" cooldown="$4" sf="$5" key="$1|$2" last num='^[1-9][0-9]{0,11}$'
  # The key can hold an evil twin's name, in any bytes: GNU grep in a UTF-8 locale hides a line
  # holding a byte that is not UTF-8 ("binary file matches"), so the ledger is read as bytes.
  last="$(LC_ALL=C grep -F "$key|" "$sf" 2>/dev/null | tail -1 | cut -d'|' -f3)"
  if [[ "$last" =~ $num ]] && [ "$now" -ge "$last" ] && [ $((now - last)) -lt "$cooldown" ]; then
    return 1
  fi
  # record this alert time (append; last-wins on read)
  printf '%s|%s\n' "$key" "$now" >> "$sf"
  return 0
}

sw_hw_notify() {
  # $1 = threat_class. Observed-syntax hardware alert; see P0 gate.
  case "$1" in
    surveillance) LED M 200 2>/dev/null ;;
    tracker)      LED Y 200 2>/dev/null ;;
    attacker)     LED R 255 2>/dev/null ;;
    *)            LED B 100 2>/dev/null ;;
  esac
  RINGTONE alert 2>/dev/null
  VIBRATE alert 2>/dev/null
  LED OFF 2>/dev/null
}

sw_emit() {
  # $1=detection $2=now $3=cooldown $4=seenfile $5=lootdir
  # Optional AUTO SNOOZE (lib/snooze.sh): $6=statefile $7=after $8=margin_db $9=reset_secs.
  # When given, a repeat full-screen alert may be HELD; the CSV row and log line never are.
  local det="$1" now="$2" cd="$3" sf="$4" loot="$5"
  local snz="${6:-}" snz_after="${7:-0}" snz_margin="${8:-7}" snz_reset="${9:-1800}"
  local cat label conf tclass radio mac ident rssi detail
  IFS='|' read -r cat label conf tclass radio mac ident rssi detail <<EOF
$det
EOF
  local color; color="$(sw_color_for "$tclass")"
  local rssitag=""; [ -n "$rssi" ] && rssitag=" ${rssi}dBm"
  # What the screen line and the alert call it. An evil twin is about WHICH network is being
  # copied, so it names that network: "Evil twin 'HomeNet'" (spec 2026-09-29 §6.4).
  # The Pager's LOG and ALERT turn the two characters \n into a line break (and no other backslash
  # pair; measured 2026-10-08), so a name sent over the air could add a line of its own to the
  # screen: there, a name's \n shows as "\ n". The CSV row and the ledger keep the name as it is.
  local bs='\' sident
  sident="${ident//"$bs"n/"$bs" n}"
  local shown="$label"
  [ "$cat" = evil_twin ] && shown="$label '$sident'"
  # A drone is named by its Remote ID, or says it sent none (spec 2026-10-01 §4). Its detail, from
  # lib/remoteid.sh (airframe TAB motion TAB pilot), adds a second screen line and the alert's body.
  local dline="" abody=""
  if [ "$cat" = drone_rid ]; then
    if [ -n "$ident" ]; then shown="$label '$sident'"; else shown="$label (no ID)"; fi
    local d_air="${detail%%$'\t'*}" d_rest="${detail#*$'\t'}" d_motion d_pilot
    d_motion="${d_rest%%$'\t'*}"; d_pilot="${d_rest#*$'\t'}"
    dline="$d_motion"; [ -n "$d_pilot" ] && dline="${dline:+$dline, }$d_pilot"
    abody="$d_air"; [ -n "$d_motion" ] && abody="${abody:+$abody, }$d_motion"
    [ -n "$abody" ] && abody="$abody"$'\n'
    [ -n "$d_pilot" ] && abody="$abody$d_pilot"$'\n'
  fi
  # The cooldown is evaluated ONCE, for every confidence level, and gates persistence.
  # It used to gate only the alert, so the loot CSV gained a row per device PER LAP
  # (~every 15s, unbounded) and a device matching two rules wrote two identical rows.
  local fresh=1
  # An evil twin's evidence is the network it copies, so each copied name is reported on its own:
  # one radio copying several names, or decoys around a real target, cannot hide one behind another
  # (spec 2026-09-29, user decision). The kind cooldown below still buzzes once for all of them.
  local rkey="$cat" rmac="$mac"
  [ "$cat" = evil_twin ] && rkey="$cat:$ident"
  # One drone = one Remote ID (user decision 2026-10-01): its key leaves out the address, which can
  # change. A drone that sends no ID is keyed by its address, like any device.
  if [ "$cat" = drone_rid ] && [ -n "$ident" ]; then rmac=drone; rkey="$cat:$ident"; fi
  sw_should_report "$rmac" "$rkey" "$now" "$cd" "$sf" && fresh=0
  [ "$fresh" -eq 0 ] && sw_log_write "$loot" "$det" "$now"
  # The colored log line still prints every lap: it is the operator's live "still here"
  # signal, and unlike the CSV it does not accumulate on disk. A lap loop that has already
  # shown enough lines of this kind sets SW_EMIT_NOLOG=1 for the call (spec 2026-09-23 §5):
  # only this line is skipped, never the CSV row or the alert.
  if [ -z "${SW_EMIT_NOLOG:-}" ]; then
    LOG "$color" "$shown $mac$rssitag" 2>/dev/null
    [ -n "$dline" ] && LOG "$color" "  $dline" 2>/dev/null
  fi
  # Full alert + hardware additionally requires high confidence, and (when snooze is on)
  # the device must not have used up its free alerts without coming closer.
  if [ "$fresh" -eq 0 ] && [ "$conf" = high ]; then
    local gate=0 note=""
    if [ -n "$snz" ]; then
      sw_snooze_gate "$mac" "$cat" "$rssi" "$now" "$snz" "$snz_after" "$snz_margin" "$snz_reset"
      gate=$?
    fi
    # One full alert per KIND per window (spec 2026-09-23 §4): this code only runs for HIGH
    # confidence (the enclosing check), so a name-only BLE Spam flood (med) never reaches it and
    # never buzzes at all -- it is a flood of HARDWARE-matched devices of one category (a room of
    # real Flippers, several Flock cameras appearing at once) that interrupts once. The kind is
    # a "*|<category>" key in the same ledger. This is the LAST gate, so that key is recorded
    # only when an alert really fires. "Following you" alerts are exempt: each follower is its
    # own possible stalker, and AUTO SNOOZE already limits it. 0 or unset = off (the lib
    # default; payload.sh owns the 600).
    local kind_cd="${SW_KIND_COOLDOWN:-0}"
    case "$kind_cd" in ''|*[!0-9]*) kind_cd=0 ;; esac
    if [ "$gate" -ne 1 ] && [ "$kind_cd" -gt 0 ]; then
      case "$cat" in
        *_follow) ;;
        *) sw_should_report "*" "$cat" "$now" "$kind_cd" "$sf" || gate=1 ;;
      esac
    fi
    if [ "$gate" -ne 1 ]; then
      [ "$gate" -eq 2 ] && note="
snoozing: re-alerts only if closer"
      ALERT "$shown
$abody$mac$rssitag$note" 2>/dev/null
      sw_hw_notify "$tclass"
    fi
  fi
}

sw_seen_prune() {
  # $1=seenfile $2=now $3=keep_secs. Drop ledger lines older than keep_secs (spec 2026-09-23
  # §7): sw_should_report holds only while now - last < cooldown, so an older line can never
  # block anything again. A line is kept only if the WHOLE line matches "key|category|<int>"
  # (mac-or-*, then category, then a plain, no-leading-zero integer timestamp -- final review
  # 2: a leading zero, e.g. "0800" or "09", reaches bash arithmetic as invalid octal and raises
  # a FATAL error, so it is excluded by shape, same as any other malformed value) AND that
  # timestamp is not in the future -- the same shape sw_should_report now insists on before
  # doing arithmetic (spec §8). Checking only the last field (the old behaviour) let a torn
  # line -- two appends fused into one by an interrupted write, e.g.
  # "AA:..|cat|<ts>BB:..|cat2|<ts2>" -- pass, since its OWN last field is still a valid recent
  # int even though the line is garbage; a future-dated line (backward clock step) also used to
  # survive, since "now - future_ts" is negative and always "< keep". Both are dropped here
  # instead of lingering.
  #
  # Two passes (final review 2, Minor 5): a READ-ONLY first pass counts what a rewrite would
  # drop and whether the file is missing its final newline (Minor 3: a ledger left without one,
  # e.g. by a power cut or a hand edit, must still be rewritten, or the next append fuses onto
  # its last line and creates exactly the torn-line shape this function exists to clean up).
  # Only when there is something to do does a SECOND pass open a temp file and actually
  # rewrite: a healthy, already-clean ledger costs one read and nothing else -- no mktemp, no
  # temp file created-then-discarded, no flash rewrite.
  #
  # Rewrites via temp + mv (like the follow and snooze state); on any failure the ledger is
  # left untouched and a WARN says so, because a ledger that silently stops shrinking grows
  # forever. rc 1 on failure. The rewrite pass writes the kept lines through ONE redirect for
  # the whole loop (open once), not an append-per-line, so a write failure (e.g. ENOSPC) is
  # caught in one place before anything touches the real ledger: an unconditional mv used to
  # succeed even when every write into the temp file had failed, replacing the ledger with an
  # empty-or-garbage file. A ledger PATH that exists but isn't a plain readable file (final
  # review 2, Minor 4: a directory, or, for a non-root process, permission-denied) is a failure
  # too, not "nothing to prune": without this check the read loop would simply never run (0
  # lines seen), which used to look exactly like an already-pruned, healthy ledger. A MISSING
  # ledger is still fine. The temp file failing to even open (as opposed to a write into an
  # already-open one failing) is caught the same way, on the rewrite loop's own redirects: a
  # loop whose redirection could not be set up at all (a missing input, or an output path that
  # can't be created) reports that failure as its own exit status.
  local sf="$1" now="$2" keep="$3" tmp line ts line_re='^[^|]+\|[^|]+\|[1-9][0-9]{0,11}$'
  # Bytes, not characters: an evil twin's key holds its network name, and in a UTF-8 locale (the
  # Pager's default) the line regex does not match a line holding a byte that is not UTF-8.
  local LC_ALL=C
  [ -e "$sf" ] || return 0
  if [ ! -f "$sf" ] || [ ! -r "$sf" ]; then
    LOG yellow "WARN: can't prune $sf — it will keep growing" 2>/dev/null; return 1
  fi
  local total=0 kept=0 no_nl=0 rd_rc
  # Both loops use if-blocks, never `continue` or `break`: this runs in the payload's main shell, and
  # bash drops a trapped SIGINT (the Pager's Stop) that lands while a loop continues or breaks.
  while IFS= read -r line; rd_rc=$?; [ "$rd_rc" -eq 0 ] || [ -n "$line" ]; do
    total=$((total + 1))
    [ "$rd_rc" -ne 0 ] && no_nl=1
    if [[ "$line" =~ $line_re ]]; then
      ts="${line##*|}"
      if [ "$ts" -le "$now" ] && [ $((now - ts)) -lt "$keep" ]; then
        kept=$((kept + 1))
      fi
    fi
  done < "$sf"
  if [ "$kept" -eq "$total" ] && [ "$no_nl" -eq 0 ]; then
    return 0
  fi
  # A name no one would type: payload.sh removes a temp copy that a Stop or a crash left behind by
  # this pattern (seen.db.sw-prune-tmp. plus six characters). The old seen.db.XXXXXX also matched a
  # hand-made seen.db.backup, and a plainer seen.db.prune.XXXXXX a seen.db.prune.before.
  if ! tmp="$(mktemp "$sf.sw-prune-tmp.XXXXXX" 2>/dev/null)"; then
    LOG yellow "WARN: can't prune $sf — it will keep growing" 2>/dev/null; return 1
  fi
  local wfail=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ $line_re ]]; then
      ts="${line##*|}"
      if [ "$ts" -le "$now" ] && [ $((now - ts)) -lt "$keep" ]; then
        printf '%s\n' "$line" || wfail=1
      fi
    fi
  done < "$sf" 2>/dev/null > "$tmp" || wfail=1
  if [ "$wfail" -eq 1 ]; then
    rm -f "$tmp"; LOG yellow "WARN: can't prune $sf — it will keep growing" 2>/dev/null; return 1
  fi
  if ! mv -f "$tmp" "$sf" 2>/dev/null; then
    rm -f "$tmp"; LOG yellow "WARN: can't prune $sf — it will keep growing" 2>/dev/null; return 1
  fi
  return 0
}

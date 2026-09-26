#!/bin/bash
# lib/match.sh — signature loading, OUI extraction, and match dispatch.
#
# PERF CONTRACT (see test/perf_test.sh): every function below runs once per record,
# and a real sweep is ~18k records on a 580MHz MIPS CPU. They must use bash builtins
# only — no pipes, no $( ). The fork-based version measured ~1.04 s/record on the
# Pager (~5.2 h per sweep). Helpers return via REPLY so callers need no subshell.

sw_load_signatures() {
  # $1 = signatures file. Strips comment/blank lines. Runs once at startup.
  grep -v '^[[:space:]]*#' "$1" 2>/dev/null | grep -v '^[[:space:]]*$'
}

sw_sanitize_ident() {
  # $1 = raw SSID / BLE name -> REPLY. Remove the record delimiter and all control
  # chars (remove, not replace, so split tokens rejoin and can't evade signatures).
  # These are BASH glob classes, not BusyBox tr classes — bash implements [:cntrl:]
  # correctly, which is why this replaces the old octal-range pipeline.
  REPLY="${1//|/}"
  REPLY="${REPLY//[[:cntrl:]]/}"
}

sw_oui() {
  # $1 = MAC (any case, colon form) -> REPLY = UPPER first 3 octets.
  REPLY="${1:0:8}"
  REPLY="${REPLY^^}"
}

_sw_lower() {
  # $1 -> REPLY lowercased.
  REPLY="${1,,}"
}

_sw_uuid_hit() {
  # $1 = normalized ble_uuid pattern, $2 = the record's token list. rc 0 = hit.
  #   xxxx     a 16-bit service UUID (uuid:xxxx) OR service data under it (sd:xxxx:*)
  #   xxxx:bb  service data whose FIRST byte is bb only. This is what keeps Eddystone
  #            beacons (feaa:10) from reading as Google Find My (feaa:41).
  #   lo-hi    inclusive numeric range over uuid: and sd: UUIDs
  local p="$1" t u lo hi
  case "$p" in
    *-*)
      lo=$((16#${p%-*})); hi=$((16#${p#*-}))
      for t in $2; do
        case "$t" in
          uuid:*) u="${t#uuid:}" ;;
          sd:*)   u="${t#sd:}"; u="${u%%:*}" ;;
          *)      continue ;;
        esac
        # Defense in depth (the parser already emits only 4-hex UUIDs): a malformed UUID
        # would raise an arithmetic error that ABORTS the caller's whole stream loop.
        case "$u" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) continue ;; esac
        u=$((16#$u))
        [ "$u" -ge "$lo" ] && [ "$u" -le "$hi" ] && return 0
      done
      return 1 ;;
    *:*) case " $2 " in *" sd:$p "*) return 0 ;; esac; return 1 ;;
    *)   case " $2 " in *" uuid:$p "*|*" sd:$p:"*) return 0 ;; esac; return 1 ;;
  esac
}

sw_prepare_sigs() {
  # $1 = signatures text. Parses ONCE into parallel arrays and pre-normalizes each
  # pattern to the case its matcher needs. Previously this normalization happened
  # per record PER signature (~40 forks/record) — the dominant cost of a sweep.
  SW_SIG_TYPE=(); SW_SIG_CAT=(); SW_SIG_LABEL=(); SW_SIG_CONF=(); SW_SIG_CLASS=(); SW_SIG_NORM=()
  local mtype pat cat label conf tclass norm
  while IFS='|' read -r mtype pat cat label conf tclass; do
    [ -n "$mtype" ] || continue
    case "$mtype" in
      wifi_oui|ble_oui) norm="${pat^^}" ;;
      *)                norm="${pat,,}" ;;
    esac
    SW_SIG_TYPE+=("$mtype"); SW_SIG_CAT+=("$cat"); SW_SIG_LABEL+=("$label")
    SW_SIG_CONF+=("$conf"); SW_SIG_CLASS+=("$tclass"); SW_SIG_NORM+=("$norm")
  done <<HEREDOC
$1
HEREDOC
}

sw_match_record() {
  # $1 = record "radio|mac|ident|rssi"  $2 = signatures text
  # Prints at most ONE detection per category: the hit with the strongest confidence
  # (high > med > low); on a tie, the rule listed first. Two rules of one category used to
  # print twice, and the first (maybe weaker) hit took the device's cooldown slot, so a med
  # name match could swallow a high hardware-prefix alert (spec 2026-09-23 §3.1).
  local rec="$1" sigs="$2"
  # Re-prepare only when the signature set actually changes (a plain string compare,
  # no fork), so a stream of records prepares once no matter which caller drives it.
  [ "${SW_SIGS_CACHE-}" = "$sigs" ] || { sw_prepare_sigs "$sigs"; SW_SIGS_CACHE="$sigs"; }
  # Split the fields with parameter expansion (ident is sanitized, so it holds no '|').
  # BLE records carry an optional 5th field of advertisement tokens (lib/ble.sh).
  local radio="${rec%%|*}" _r="${rec#*|}"
  local mac="${_r%%|*}" _r2="${_r#*|}"
  local ident="${_r2%%|*}" _r3="${_r2#*|}"
  local rssi="${_r3%%|*}" adv=""
  [ "$_r3" = "$rssi" ] || adv="${_r3#*|}"
  local oui="${mac:0:8}"; oui="${oui^^}"
  local lident="${ident,,}"
  local i j hit mtype norm rank
  local -a best_cat=() best_rank=() best_i=()   # one slot per category hit, first-hit order
  for (( i=0; i<${#SW_SIG_TYPE[@]}; i++ )); do
    hit=1; mtype="${SW_SIG_TYPE[i]}"; norm="${SW_SIG_NORM[i]}"
    case "$mtype" in
      wifi_oui)      [ "$radio" = wifi ] && [ "$norm" = "$oui" ] && hit=0 ;;
      ble_oui)       [ "$radio" = ble  ] && [ "$norm" = "$oui" ] && hit=0 ;;
      wifi_ssid_sub) if [ "$radio" = wifi ] && [ -n "$ident" ] && [ -n "$norm" ]; then case "$lident" in *"$norm"*) hit=0;; esac; fi ;;
      wifi_ssid_pre) if [ "$radio" = wifi ] && [ -n "$ident" ] && [ -n "$norm" ]; then case "$lident" in "$norm"*) hit=0;; esac; fi ;;
      ble_name_sub)  if [ "$radio" = ble  ] && [ -n "$ident" ] && [ -n "$norm" ]; then case "$lident" in *"$norm"*) hit=0;; esac; fi ;;
      # Tier-3 (spec §4). ble_mfr is a WHOLE-SEGMENT prefix: equal, or followed by ':'.
      # A plain string prefix would let 004c:12:2 (near owner) match 004c:12:25 (separated).
      ble_mfr)       if [ "$radio" = ble ] && [ -n "$adv" ]; then case " $adv " in *" mfr:$norm "*|*" mfr:$norm:"*) hit=0;; esac; fi ;;
      ble_uuid)      [ "$radio" = ble ] && [ -n "$adv" ] && _sw_uuid_hit "$norm" "$adv" && hit=0 ;;
      *) : ;;   # unknown match_type: ignored (test/signatures_test.sh rejects unknown types)
    esac
    [ "$hit" -eq 0 ] || continue
    case "${SW_SIG_CONF[i]}" in high) rank=3 ;; med) rank=2 ;; low) rank=1 ;; *) rank=0 ;; esac
    for (( j=0; j<${#best_cat[@]}; j++ )); do [ "${best_cat[j]}" = "${SW_SIG_CAT[i]}" ] && break; done
    if [ "$j" -eq "${#best_cat[@]}" ]; then
      best_cat+=("${SW_SIG_CAT[i]}"); best_rank+=("$rank"); best_i+=("$i")
    elif [ "$rank" -gt "${best_rank[j]}" ]; then
      best_rank[j]="$rank"; best_i[j]="$i"
    fi
  done
  for (( j=0; j<${#best_i[@]}; j++ )); do
    i="${best_i[j]}"
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
      "${SW_SIG_CAT[i]}" "${SW_SIG_LABEL[i]}" "${SW_SIG_CONF[i]}" "${SW_SIG_CLASS[i]}" \
      "$radio" "$mac" "$ident" "$rssi"
  done
}

sw_match_stream() {
  # $1 = signatures text; reads records on stdin
  local sigs="$1" rec
  while IFS= read -r rec; do
    [ -n "$rec" ] && sw_match_record "$rec" "$sigs"
  done
}

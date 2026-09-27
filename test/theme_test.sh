# test/theme_test.sh — the SquachWatch theme installer, run under POSIX sh against a SYNTHETIC stock
# theme written here (no Hak5 files needed), plus header checks of the two shipped pictures.
_th_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
_th_inst="$_th_root/themes/SquachWatch/install.sh"
_th_tmp="$(mktemp -d)"

_th_mkstock() {  # $1 = folder to create: a minimal stock theme with the files install.sh patches
  mkdir -p "$1/components/alerts" "$1/components/templates" "$1/assets/payloadlog"
  cat > "$1/theme.json" <<'J'
{"theme_version": "1.1.0",
 "payload_log_path": "components/payload_log.json",
 "alert_dialog_path": "components/alerts/alert_info_dialog.json",
 "string_templates": {"alert_info_dialog_text": "components/templates/alert_info_dialog_text.json",
                      "timestamp": "components/templates/timestamp.json"},
 "color_palette": {"magenta": {"r": 205, "g": 85, "b": 155}, "yellow": {"r": 231, "g": 197, "b": 74},
                   "cyan": {"r": 96, "g": 205, "b": 205}, "green": {"r": 42, "g": 180, "b": 42},
                   "red": {"r": 250, "g": 72, "b": 9}, "black": {"r": 0, "g": 0, "b": 0}}}
J
  cat > "$1/components/payload_log.json" <<'J'
{"background": {"layers": [{"image_path": "assets/payloadlog/payload_log_bg.png", "x": 0, "y": 0},
                           {"variable_name": "$_INPUT_NAME", "use_template": "payload_title", "x": 0, "y": 0}]},
 "scroll_up_indicator": [{"image_path": "assets/payloadlog/scroll_up_indicator.png", "x": 465, "y": 40}],
 "visible_lines": 14, "max_chars": 50, "start_x": 6, "start_y": 24}
J
  cat > "$1/components/alerts/alert_info_dialog.json" <<'J'
{"windowed_canvas": true,
 "background": {"layers": [{"image_path": "assets/alert_dialog_bg_term_blue.png", "x": 28, "y": 0}]}}
J
  cat > "$1/components/templates/alert_info_dialog_text.json" <<'J'
{"text_size": "small", "text_color_palette": "yellow", "max_chars": 42, "wrap_text": true, "max_lines": 13,
 "center_text_within": {"draw_bounds": false, "start_x": 80, "end_x": 400, "start_y": 26, "end_y": 190}}
J
  cat > "$1/components/templates/timestamp.json" <<'J'
{"text_size": "small", "text_color_palette": "gray", "max_chars": 20, "wrap_text": false, "max_lines": 1}
J
  printf '{"untouched": true}\n' > "$1/components/lock_screen.json"
  printf 'stock picture\n' > "$1/assets/payloadlog/payload_log_bg.png"
  printf 'stock picture\n' > "$1/assets/payloadlog/scroll_up_indicator.png"
  printf 'stock picture\n' > "$1/assets/alert_dialog_bg_term_blue.png"
}
_th_run() {  # $1 = stock folder, $2 = destination; prints install.sh's exit code
  SW_THEME_STOCK="$1" SW_THEME_DEST="$2" sh "$_th_inst" >/dev/null 2>&1; echo "$?"
}
_th_err() {  # $1 = stock folder, $2 = destination; prints only what install.sh writes to stderr
  SW_THEME_STOCK="$1" SW_THEME_DEST="$2" sh "$_th_inst" 2>&1 >/dev/null
}
_th_sum() { (cd "$1" && find . -type f | LC_ALL=C sort | xargs md5sum) 2>/dev/null | md5sum | cut -c1-32; }
_th_png() {  # $1 = PNG -> "width height bitdepth colourtype" from its IHDR chunk
  od -An -tu1 -j16 -N10 "$1" | awk '{printf "%d %d %d %d", $1*16777216+$2*65536+$3*256+$4, $5*16777216+$6*65536+$7*256+$8, $9, $10}'
}

# --- a good install ---
_th_mkstock "$_th_tmp/stock"
_th_d="$_th_tmp/themes/SquachWatch"
assert_eq "$(_th_run "$_th_tmp/stock" "$_th_d")" "0" theme_install_ok
assert_eq "$(jq -r '.background.layers[0].image_path' "$_th_d/components/payload_log.json")" \
  "assets/squachwatch/payload_bg.png" theme_payload_bg_patched
assert_eq "$(jq -r '.background.layers[1].variable_name' "$_th_d/components/payload_log.json")" \
  '$_INPUT_NAME' theme_payload_title_layer_kept
assert_eq "$(jq -c '[.visible_lines, .max_chars, .start_x, .start_y]' "$_th_d/components/payload_log.json")" \
  '[14,36,6,24]' theme_payload_text_settings
assert_eq "$(jq -r '.background.layers[0].image_path' "$_th_d/components/alerts/alert_info_dialog.json")" \
  "assets/squachwatch/alert_card.png" theme_alert_card_patched
assert_eq "$(jq -c '[.text_color_palette, .max_chars, .max_lines, .wrap_text, .center_text_within]' \
  "$_th_d/components/templates/alert_info_dialog_text.json")" \
  '["cyan",26,8,true,{"draw_bounds":false,"start_x":44,"end_x":296,"start_y":58,"end_y":196}]' \
  theme_alert_text_inside_the_plate
assert_eq "$(jq -c '[.text_color_palette, .max_chars, .text_size]' "$_th_d/components/templates/timestamp.json")" \
  '["black",20,"small"]' theme_alert_time_black
assert_eq "$(jq -c '.color_palette | [.magenta, .yellow, .cyan, .green]' "$_th_d/theme.json")" \
  '[{"r":255,"g":113,"b":206},{"r":255,"g":251,"b":148},{"r":0,"g":255,"b":255},{"r":0,"g":255,"b":0}]' \
  theme_palette_neon
assert_eq "$(jq -c '.color_palette.red' "$_th_d/theme.json")" '{"r":250,"g":72,"b":9}' theme_palette_red_kept
assert_eq "$(cat "$_th_d/components/lock_screen.json")" '{"untouched": true}' theme_other_component_untouched
assert_eq "$(cmp -s "$_th_d/assets/squachwatch/payload_bg.png" "$_th_root/themes/SquachWatch/assets/payload_bg.png" && echo same)" \
  same theme_payload_picture_copied
assert_eq "$(cmp -s "$_th_d/assets/squachwatch/alert_card.png" "$_th_root/themes/SquachWatch/assets/alert_card.png" && echo same)" \
  same theme_alert_picture_copied
assert_eq "$(ls -A "$_th_tmp/themes" | tr '\n' ' ')" "SquachWatch " theme_no_temp_folder_left
assert_eq "$(jq -r '.background.layers[0].image_path' "$_th_tmp/stock/components/payload_log.json")" \
  "assets/payloadlog/payload_log_bg.png" theme_stock_left_untouched

# --- running it again gives the same result; control: the checksum does see a change ---
_th_s1="$(_th_sum "$_th_d")"
assert_eq "$(_th_run "$_th_tmp/stock" "$_th_d")" "0" theme_reinstall_ok
assert_eq "$(_th_sum "$_th_d")" "$_th_s1" theme_reinstall_same_result
printf 'x' >> "$_th_d/components/lock_screen.json"
assert_eq "$([ "$(_th_sum "$_th_d")" != "$_th_s1" ] && echo differs)" differs theme_sum_control_sees_a_change

# --- failures: exit 1, no temporary folder left, the existing theme untouched ---
printf 'marker\n' > "$_th_d/MARKER"
_th_s2="$(_th_sum "$_th_d")"
cp -r "$_th_tmp/stock" "$_th_tmp/stock_nolog"; rm "$_th_tmp/stock_nolog/components/payload_log.json"
assert_eq "$(_th_run "$_th_tmp/stock_nolog" "$_th_d")" "1" theme_missing_component_fails
assert_eq "$(_th_sum "$_th_d")" "$_th_s2" theme_missing_component_keeps_old
assert_eq "$(ls -A "$_th_tmp/themes" | tr '\n' ' ')" "SquachWatch " theme_missing_component_no_temp
cp -r "$_th_tmp/stock" "$_th_tmp/stock_badjson"; printf '{' > "$_th_tmp/stock_badjson/components/lock_screen.json"
assert_eq "$(_th_run "$_th_tmp/stock_badjson" "$_th_d")" "1" theme_bad_json_fails
assert_eq "$(_th_sum "$_th_d")" "$_th_s2" theme_bad_json_keeps_old
assert_eq "$(ls -A "$_th_tmp/themes" | tr '\n' ' ')" "SquachWatch " theme_bad_json_no_temp
cp -r "$_th_tmp/stock" "$_th_tmp/stock_noimg"; rm "$_th_tmp/stock_noimg/assets/payloadlog/scroll_up_indicator.png"
assert_eq "$(_th_run "$_th_tmp/stock_noimg" "$_th_d")" "1" theme_missing_picture_fails
assert_eq "$(_th_sum "$_th_d")" "$_th_s2" theme_missing_picture_keeps_old
assert_eq "$(ls -A "$_th_tmp/themes" | tr '\n' ' ')" "SquachWatch " theme_missing_picture_no_temp
# ...and each failure says why, on stderr
assert_contains "$(_th_err "$_th_tmp/stock_nolog" "$_th_d")" \
  "SquachWatch theme NOT installed: the stock theme has no components/payload_log.json" theme_missing_component_says_why
assert_contains "$(_th_err "$_th_tmp/stock_badjson" "$_th_d")" \
  "SquachWatch theme NOT installed: invalid JSON: components/lock_screen.json" theme_bad_json_says_why
assert_contains "$(_th_err "$_th_tmp/stock_noimg" "$_th_d")" \
  "SquachWatch theme NOT installed: missing picture(s): assets/payloadlog/scroll_up_indicator.png" theme_missing_picture_says_why
# control: a good install reports success on stdout and nothing on stderr
_th_out="$(SW_THEME_STOCK="$_th_tmp/stock" SW_THEME_DEST="$_th_tmp/quiet/SquachWatch" sh "$_th_inst" 2>"$_th_tmp/err")"
assert_contains "$_th_out" "SquachWatch theme installed in $_th_tmp/quiet/SquachWatch" theme_good_install_says_so
assert_empty "$(cat "$_th_tmp/err")" theme_good_install_no_stderr
# control: a good install DOES replace that destination (so "untouched" above is not vacuous)
assert_eq "$(_th_run "$_th_tmp/stock" "$_th_d")" "0" theme_control_good_install
assert_eq "$([ -e "$_th_d/MARKER" ] && echo still || echo gone)" gone theme_control_old_theme_replaced

# --- symlinked stock theme: cp -rL must copy it, not patch the real stock dir through the link ---
ln -s "$_th_tmp/stock" "$_th_tmp/stock_symlink"
_th_realsum="$(_th_sum "$_th_tmp/stock")"
_th_symd="$_th_tmp/more/Sym"
assert_eq "$(_th_run "$_th_tmp/stock_symlink" "$_th_symd")" "0" theme_symlinked_stock_installs_ok
assert_eq "$(_th_sum "$_th_tmp/stock")" "$_th_realsum" theme_symlinked_stock_real_unpatched
assert_eq "$([ -d "$_th_symd" ] && [ ! -L "$_th_symd" ] && echo real_dir)" real_dir theme_symlinked_stock_dest_not_a_symlink

# --- interrupted install: a signal mid-build must not corrupt or vanish an existing destination ---
# A jq wrapper that sleeps first (found via PATH ahead of the real one) gives the installer's many jq
# calls enough wall-clock time to reliably catch it mid-build with a signal.
_th_realjq="$(command -v jq)"
mkdir -p "$_th_tmp/jqwrap"
cat > "$_th_tmp/jqwrap/jq" <<EOF
#!/bin/sh
sleep 0.3
exec "$_th_realjq" "\$@"
EOF
chmod +x "$_th_tmp/jqwrap/jq"
_th_intd="$_th_tmp/more/Interrupt"
_th_mkstock "$_th_intd"
printf 'marker\n' > "$_th_intd/MARKER"
_th_ints1="$(_th_sum "$_th_intd")"
PATH="$_th_tmp/jqwrap:$PATH" SW_THEME_STOCK="$_th_tmp/stock" SW_THEME_DEST="$_th_intd" sh "$_th_inst" \
  >/dev/null 2>&1 &
_th_intpid=$!
sleep 1
_th_intalive="$(kill -0 "$_th_intpid" 2>/dev/null && echo alive)"
kill -HUP "$_th_intpid" 2>/dev/null
wait "$_th_intpid"
_th_intrc=$?
assert_eq "$_th_intalive" alive theme_interrupt_still_running_before_signal
assert_eq "$_th_intrc" "1" theme_interrupted_install_fails
assert_empty "$(find "$_th_tmp/more" -maxdepth 1 -name '.*.tmp.*')" theme_interrupted_no_tmp_left
assert_eq "$(_th_sum "$_th_intd")" "$_th_ints1" theme_interrupted_dest_unchanged

# --- guarded time-black patch: skip (not fail) when either precondition is unsafe, and say so ---
cp -r "$_th_tmp/stock" "$_th_tmp/stock_noblack"
jq 'del(.color_palette.black)' "$_th_tmp/stock/theme.json" > "$_th_tmp/stock_noblack/theme.json"
_th_nbd="$_th_tmp/more/NoBlack"
SW_THEME_STOCK="$_th_tmp/stock_noblack" SW_THEME_DEST="$_th_nbd" sh "$_th_inst" \
  >"$_th_tmp/nb.out" 2>"$_th_tmp/nb.err"
_th_nbrc=$?
assert_eq "$_th_nbrc" "0" theme_noblack_install_ok
assert_eq "$(jq -r '.text_color_palette' "$_th_nbd/components/templates/timestamp.json")" "gray" theme_noblack_time_unpatched
assert_contains "$(cat "$_th_tmp/nb.out")" "note" theme_noblack_note_printed
assert_empty "$(cat "$_th_tmp/nb.err")" theme_noblack_no_stderr

cp -r "$_th_tmp/stock" "$_th_tmp/stock_seconduse"
jq '. + {"use_template": "timestamp"}' "$_th_tmp/stock/components/lock_screen.json" \
  > "$_th_tmp/stock_seconduse/components/lock_screen.json"
_th_sud="$_th_tmp/more/SecondUse"
SW_THEME_STOCK="$_th_tmp/stock_seconduse" SW_THEME_DEST="$_th_sud" sh "$_th_inst" \
  >"$_th_tmp/su.out" 2>"$_th_tmp/su.err"
_th_surc=$?
assert_eq "$_th_surc" "0" theme_seconduse_install_ok
assert_eq "$(jq -r '.text_color_palette' "$_th_sud/components/templates/timestamp.json")" "gray" theme_seconduse_time_unpatched
assert_contains "$(cat "$_th_tmp/su.out")" "note" theme_seconduse_note_printed
assert_empty "$(cat "$_th_tmp/su.err")" theme_seconduse_no_stderr

# --- the shipped pictures: size and 8-bit palette (PNG colour type 3) ---
assert_eq "$(_th_png "$_th_root/themes/SquachWatch/assets/payload_bg.png")" "480 222 8 3" theme_payload_png_header
assert_eq "$(_th_png "$_th_root/themes/SquachWatch/assets/alert_card.png")" "429 222 8 3" theme_alert_png_header

rm -rf "$_th_tmp"
unset -f _th_mkstock _th_run _th_err _th_sum _th_png
unset _th_root _th_inst _th_tmp _th_d _th_s1 _th_s2 _th_out
unset _th_realsum _th_symd _th_realjq _th_intd _th_ints1 _th_intpid _th_intalive _th_intrc
unset _th_nbd _th_nbrc _th_sud _th_surc

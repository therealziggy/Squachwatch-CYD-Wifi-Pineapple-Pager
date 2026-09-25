#!/bin/bash
# Title: SquachWatch Client Alert
# Description: Alert + vendor lookup when a client associates.
OUI_FILE="${SW_OUI_FILE:-/lib/hak5/oui.txt}"; [ -f "$OUI_FILE" ] || OUI_FILE=/rom/lib/hak5/oui.txt
mac="${_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS}"
vendor="Unknown"
if [ -f "$OUI_FILE" ]; then
  # P0-confirmed format: colon-form OUIs, TAB-separated, vendor in field 2. Key = first
  # 3 octets in colon form (e.g. D6:12:5A). Anchor ^ so we can't match mid-line.
  key="$(printf '%s' "$mac" | cut -c1-8 | tr 'a-z' 'A-Z')"
  [ -n "$key" ] && v="$(grep -i "^$key" "$OUI_FILE" 2>/dev/null | head -1 | cut -f2)"
  [ -n "$v" ] && vendor="$v"
fi
LOG yellow "Client ${mac} (${vendor}) -> ${_ALERT_CLIENT_CONNECTED_SSID}" 2>/dev/null
ALERT "CLIENT CONNECTED
${mac}
${vendor}
SSID: ${_ALERT_CLIENT_CONNECTED_SSID}" 2>/dev/null
exit 0

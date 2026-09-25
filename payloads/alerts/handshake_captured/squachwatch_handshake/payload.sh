#!/bin/bash
# Title: SquachWatch Handshake Alert
LOG cyan "Handshake ${_ALERT_HANDSHAKE_TYPE} ap ${_ALERT_HANDSHAKE_AP_MAC_ADDRESS}" 2>/dev/null
ALERT "HANDSHAKE ${_ALERT_HANDSHAKE_TYPE}
ap ${_ALERT_HANDSHAKE_AP_MAC_ADDRESS}" 2>/dev/null
exit 0

#!/bin/bash
# Title: SquachWatch Deauth Alert
# Description: Full-screen alert on a deauth flood (SquachWatch attacker class).
LOG cyan "Deauth flood: src ${_ALERT_DENIAL_SOURCE_MAC_ADDRESS} -> ap ${_ALERT_DENIAL_AP_MAC_ADDRESS}" 2>/dev/null
ALERT "DEAUTH FLOOD
src ${_ALERT_DENIAL_SOURCE_MAC_ADDRESS}
ap  ${_ALERT_DENIAL_AP_MAC_ADDRESS}" 2>/dev/null
RINGTONE alert 2>/dev/null
exit 0

#!/bin/bash
# Title: SquachWatch Auth Alert
LOG cyan "Auth captured: ${_ALERT_AUTH_SUMMARY:-${_ALERT_AUTH_TYPE:-credential}}${_ALERT_AUTH_USERNAME:+ user=${_ALERT_AUTH_USERNAME}}" 2>/dev/null
ALERT "AUTH CAPTURED
${_ALERT_AUTH_SUMMARY:-${_ALERT_AUTH_TYPE:-credential}}${_ALERT_AUTH_USERNAME:+
user: ${_ALERT_AUTH_USERNAME}}" 2>/dev/null
RINGTONE alert 2>/dev/null
exit 0

#!/usr/bin/env bash
# W02 -- Console login WITHOUT MFA, including 2-4 mistyped passwords. Actor: IAMUser carol.
# Plan: "1/day, ~3 days of the 14"; "ATH-005 only if a burst reaches 10 failures in
# 10 min; the declared cadence stays under it."
#
# Operator-assisted for the same reason as W01. The mistyped passwords are deliberate and
# are part of the declared workflow, not an accident: 2-4 of them, which is under
# ATH-005's threshold of 10 failures in 10 minutes (base.py:39).
#
#   ./W02_console_login_no_mfa.sh --session-id D03-W02-1 --mistypes 3
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
MISTYPES="${ATH_ARG_mistypes:-3}"
if (( MISTYPES < 2 || MISTYPES > 4 )); then
  ath_die "--mistypes must be 2-4: the plan declares 2-4, and 10 in 10 minutes is ATH-005's threshold"
fi

ath_session_start "W02 console login without MFA as carol, ${MISTYPES} mistyped passwords"
ath_manual_step "sign in as carol at https://console.aws.amazon.com/ and mistype the password ${MISTYPES} time(s)"
ath_manual_step "then sign in successfully, look at one page, and sign out"
ath_session_end done "${MISTYPES} failed ConsoleLogin then one success"

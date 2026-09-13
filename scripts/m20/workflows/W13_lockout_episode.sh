#!/usr/bin/env bash
# W13 -- Lockout episode: carol mistypes 12 times in 6 minutes, then resets and logs in.
# Actor: IAMUser carol. Day 6, 13 events.
#   ATH-005 expected, HIGH: "A user whose phone or mapped drive holds an old password
#            after a reset"; "Account lockout thresholds causing repeated failures after a
#            single mistake."
#
# Operator-assisted, like W01 and W02: ConsoleLogin comes from a browser sign-in and no
# aws-cli call produces one. This script paces the episode, records the session, and keeps
# the count honest -- ATH-005's threshold is 10 failures in 10 minutes with a success
# within 15 (base.py:39,43,46), and the plan declares 12 failures in 6 minutes, so the
# episode must be *over* the threshold and is meant to be.
#
#   ./W13_lockout_episode.sh --session-id D06-W13-1 --failures 12 --minutes 6
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
FAILURES="${ATH_ARG_failures:-12}"
MINUTES="${ATH_ARG_minutes:-6}"
if (( FAILURES < 10 )); then
  ath_die "--failures must be >= 10: the plan declares 12, and ATH-005 needs 10 in 10 minutes"
fi

SPACING=$(( MINUTES * 60 / FAILURES ))

ath_session_start "W13 lockout: ${FAILURES} failed console logins in ${MINUTES} min, then a reset and a success"
echo "Sign in as carol at https://console.aws.amazon.com/ and mistype the password when prompted."
echo "This script paces the attempts: ${FAILURES} attempts, one every ${SPACING}s."
for attempt in $(seq 1 "$FAILURES"); do
  ath_manual_step "attempt ${attempt}/${FAILURES}: submit the WRONG password"
  if [[ "$ATH_DRY_RUN" != "1" && "$attempt" -lt "$FAILURES" ]]; then
    sleep "$SPACING"
  fi
done
ath_manual_step "reset carol's console password (IAM console, as an administrator)"
ath_manual_step "sign in as carol with the new password, then sign out"

ath_session_end done "${FAILURES} failed ConsoleLogin in ${MINUTES} min, password reset, then success"

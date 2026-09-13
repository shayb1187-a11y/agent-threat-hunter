#!/usr/bin/env bash
# W01 -- Console login WITH MFA. Actors: IAMUser alice, bob. 1-3/day each, business hours.
# Plan: "signin ConsoleLogin, write"; rules that could fire: none expected.
#
# Operator-assisted, and it has to be: ConsoleLogin is emitted by the AWS sign-in service
# when a human authenticates in a browser. There is no aws-cli call that produces one
# (sts get-federation-token produces GetFederationToken, a different event with a
# different identity type), so a script that "performed" W01 would be performing
# something else. This script records the session and tells the operator what to do.
#
#   ./W01_console_login_mfa.sh --session-id D03-W01-1 --user alice --profile ath-m20
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
USER_NAME="${ATH_ARG_user:-alice}"

ath_session_start "W01 console login with MFA as ${USER_NAME}"
ath_manual_step "sign in to the console as ${USER_NAME} with MFA, at https://console.aws.amazon.com/"
ath_manual_step "open two or three console pages you would normally open (EC2, S3), then sign out"
# One cheap API call from the same identity, so the session leaves a control-plane row
# as well as the signin row; ATH routes ConsoleLogin to the logon table only.
ath_aws sts get-caller-identity >/dev/null
ath_session_end done "console login with MFA completed by hand"

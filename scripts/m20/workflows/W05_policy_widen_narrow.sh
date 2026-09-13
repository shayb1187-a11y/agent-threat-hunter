#!/usr/bin/env bash
# W05 -- Benign policy modification: widen then narrow a role's policy as its job changes.
# Actor: AssumedRole AdminRole. Plan: ~12 calls, 2 sessions.
#   AWS-005 "Policy churn during development, where a role's permissions are attached and
#            detached repeatedly while someone works out what it needs."
#
#   ./W05_policy_widen_narrow.sh --session-id D05-W05-1 \
#       --role-arn arn:aws:iam::012345678901:role/AdminRole --target-role ReportingRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
TARGET_ROLE="${ATH_ARG_target_role:-ReportingRole}"
POLICY_NAME="${ATH_ARG_policy_name:-ath-m20-reporting-inline}"
[[ -n "$ATH_ROLE_ARN" ]] || ath_die "--role-arn (the AdminRole to assume) is required"

WIDE="$(cat "${ATH_WORKFLOWS_DIR}/policies/w05_wide.json")"
NARROW="$(cat "${ATH_WORKFLOWS_DIR}/policies/w05_narrow.json")"

ath_session_start "W05 widen then narrow the inline policy of ${TARGET_ROLE}"
ath_assume_role "$ATH_ROLE_ARN" "ath-m20-admin"

ath_aws iam get-role --role-name "$TARGET_ROLE" >/dev/null
ath_aws iam list-role-policies --role-name "$TARGET_ROLE" >/dev/null
# Widen: the role picked up a new job this week.
ath_aws iam put-role-policy --role-name "$TARGET_ROLE" \
  --policy-name "$POLICY_NAME" --policy-document "$WIDE"
ath_aws iam get-role-policy --role-name "$TARGET_ROLE" --policy-name "$POLICY_NAME" >/dev/null
# Narrow again: least privilege catches up once it is clear what the job needs. The
# delete/put pair is the churn the plan quotes AWS-005's false_positives about.
ath_aws iam put-role-policy --role-name "$TARGET_ROLE" \
  --policy-name "$POLICY_NAME" --policy-document "$NARROW"
ath_aws iam delete-role-policy --role-name "$TARGET_ROLE" --policy-name "$POLICY_NAME"
ath_aws iam put-role-policy --role-name "$TARGET_ROLE" \
  --policy-name "$POLICY_NAME" --policy-document "$NARROW"
ath_aws iam list-role-policies --role-name "$TARGET_ROLE" >/dev/null
ath_session_end done "policy widened then narrowed on ${TARGET_ROLE}"

#!/usr/bin/env bash
# W04 -- IAM administration: create user/role/group, attach/detach policies, rotate keys.
# Actor: AssumedRole AdminRole. Plan: ~30 calls, 3 sessions over 14 days.
# Rules the plan expects may fire, quoting the rules' own false_positives:
#   AWS-001 "Routine onboarding: an administrator grants a new identity permissions, and
#            that identity (or a provisioning script) creates its first access key
#            shortly after as part of normal setup."
#   AWS-005 "Routine deprovisioning... Least-privilege cleanup campaigns"
#
# Three modes, one per scheduled session: onboard (day 2), rotate (day 8), offboard
# (day 12). The schedule's day-12 row names the offboarding explicitly.
#
#   ./W04_iam_administration.sh --session-id D02-W04-1 --mode onboard --user dave \
#       --role-arn arn:aws:iam::012345678901:role/AdminRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
MODE="${ATH_ARG_mode:?--mode must be onboard, rotate or offboard}"
NEW_USER="${ATH_ARG_user:-dave}"
GROUP="${ATH_ARG_group:-ath-m20-developers}"
READONLY_POLICY="arn:aws:iam::aws:policy/ReadOnlyAccess"

[[ -n "$ATH_ROLE_ARN" ]] || ath_die "--role-arn (the AdminRole to assume) is required"
ath_session_start "W04 ${MODE} (${NEW_USER})"
ath_assume_role "$ATH_ROLE_ARN" "ath-m20-admin"

case "$MODE" in
  onboard)
    ath_aws iam create-group --group-name "$GROUP" || true
    ath_aws iam attach-group-policy --group-name "$GROUP" --policy-arn "$READONLY_POLICY"
    ath_aws iam create-user --user-name "$NEW_USER"
    ath_aws iam add-user-to-group --group-name "$GROUP" --user-name "$NEW_USER"
    ath_aws iam attach-user-policy --user-name "$NEW_USER" --policy-arn "$READONLY_POLICY"
    # The grant-then-key pair the plan predicts AWS-001 may fire on. It is ordinary
    # onboarding: the new identity needs a key to do its job.
    ath_aws iam create-access-key --user-name "$NEW_USER" >/dev/null
    ath_aws iam list-attached-user-policies --user-name "$NEW_USER" >/dev/null
    ath_aws iam get-user --user-name "$NEW_USER" >/dev/null
    ;;
  rotate)
    OLD_KEY="$(ath_aws iam list-access-keys --user-name "$NEW_USER" \
      --query "AccessKeyMetadata[0].AccessKeyId" --output text)"
    ath_aws iam create-access-key --user-name "$NEW_USER" >/dev/null
    if [[ -n "$OLD_KEY" && "$OLD_KEY" != "None" ]]; then
      ath_aws iam update-access-key --user-name "$NEW_USER" \
        --access-key-id "$OLD_KEY" --status Inactive
      ath_aws iam delete-access-key --user-name "$NEW_USER" --access-key-id "$OLD_KEY"
    fi
    ath_aws iam list-access-keys --user-name "$NEW_USER" >/dev/null
    ;;
  offboard)
    for key in $(ath_aws iam list-access-keys --user-name "$NEW_USER" \
        --query "AccessKeyMetadata[].AccessKeyId" --output text); do
      ath_aws iam delete-access-key --user-name "$NEW_USER" --access-key-id "$key"
    done
    ath_aws iam detach-user-policy --user-name "$NEW_USER" --policy-arn "$READONLY_POLICY"
    ath_aws iam remove-user-from-group --group-name "$GROUP" --user-name "$NEW_USER"
    ath_aws iam delete-user --user-name "$NEW_USER"
    ath_aws iam detach-group-policy --group-name "$GROUP" --policy-arn "$READONLY_POLICY"
    ath_aws iam delete-group --group-name "$GROUP"
    ;;
  *) ath_die "--mode must be onboard, rotate or offboard" ;;
esac
ath_session_end done "W04 ${MODE} complete"

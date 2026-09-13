#!/usr/bin/env bash
# W12 -- Malformed-policy iteration: an engineer hand-edits a trust policy and the
# platform rejects it 6 times before accepting. Actor: IAMUser bob. Day 8, 7 calls.
#   AWS-006 expected: "An engineer iterating on a trust policy or a permission boundary by
#            hand until the platform accepts it."
#
# The six rejections are genuine MalformedPolicyDocument / validation errors, which
# CloudTrail records with an errorCode and ATH's adapter classifies as decision=failed
# (control_vocab.classify_error), not denied. AWS-006's threshold is 5 failed writes
# (base.py:119), so six rejections is one over it -- which is what the plan predicts, and
# the reason the workflow is in the corpus at all.
#
# The attempts are in policies/w12_attempts/, numbered, each broken in a different
# ordinary way (a typo, a missing field, a bad principal). They are not crafted to defeat
# anything; they are what a hand-edited trust policy looks like while it is wrong.
#
#   ./W12_malformed_policy_iteration.sh --session-id D08-W12-1 --target-role ReportingRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
TARGET_ROLE="${ATH_ARG_target_role:-ReportingRole}"
ATTEMPTS_DIR="${ATH_WORKFLOWS_DIR}/policies/w12_attempts"
[[ -d "$ATTEMPTS_DIR" ]] || ath_die "missing ${ATTEMPTS_DIR}"

ath_session_start "W12 trust-policy iteration on ${TARGET_ROLE}: six rejections, then one that is accepted"

rejected=0
for attempt in "${ATTEMPTS_DIR}"/reject_*.json; do
  ath_aws_expect_failure "$(basename "$attempt")" \
    iam update-assume-role-policy --role-name "$TARGET_ROLE" \
    --policy-document "file://${attempt}"
  rejected=$((rejected + 1))
done

# The seventh call is the one that works, which is what makes this an iteration rather
# than a failure: the engineer got there.
ath_aws iam update-assume-role-policy --role-name "$TARGET_ROLE" \
  --policy-document "file://${ATTEMPTS_DIR}/accept.json"
ath_aws iam get-role --role-name "$TARGET_ROLE" >/dev/null

ath_session_end done "${rejected} rejected trust policies, then one accepted"

#!/usr/bin/env bash
# W03 -- Role assumption chain: user -> DeveloperRole -> DeployRole.
# Actors: IAMUser alice -> AssumedRole. Plan: 5-15/day, "sts AssumeRole, write";
# "none; feeds the actor identity of most other workflows".
#
#   ./W03_role_chain.sh --session-id D03-W03-1 \
#       --developer-role-arn arn:aws:iam::012345678901:role/DeveloperRole \
#       --deploy-role-arn    arn:aws:iam::012345678901:role/DeployRole --rounds 5
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
DEV_ROLE="${ATH_ARG_developer_role_arn:?--developer-role-arn is required}"
DEPLOY_ROLE="${ATH_ARG_deploy_role_arn:?--deploy-role-arn is required}"
ROUNDS="${ATH_ARG_rounds:-5}"

ath_session_start "W03 role chain alice -> DeveloperRole -> DeployRole, ${ROUNDS} round(s)"
for i in $(seq 1 "$ROUNDS"); do
  echo "round ${i}/${ROUNDS}"
  # Each round is a fresh chain, which is what a day of normal work looks like: the
  # developer's session expires and the tooling assumes the role again.
  ( ath_assume_role "$DEV_ROLE" "ath-m20-dev"
    ath_aws sts get-caller-identity >/dev/null
    ath_assume_role "$DEPLOY_ROLE" "ath-m20-deploy"
    ath_aws sts get-caller-identity >/dev/null )
done
ath_session_end done "${ROUNDS} chained assumptions"

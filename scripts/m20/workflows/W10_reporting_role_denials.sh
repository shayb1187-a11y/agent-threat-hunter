#!/usr/bin/env bash
# W10 -- Least-privilege role probing its own permissions: a newly scoped-down
# ReportingRole runs its normal daily job; calls outside its policy are denied.
# Actor: AssumedRole ReportingRole. Plan: ~40 calls/day of which ~28 denied, in <10 min.
#   AWS-004 expected to fire, HIGH (>=5 resource types): "A pipeline or application whose
#            role is missing a permission, retrying the call it cannot make -- by far the
#            most common cause of denial runs"; "A newly created or newly scoped-down role
#            exercising paths its old policy allowed, until the code catches up with the
#            policy."
#
# Nothing here is shaped to trip the rule: the allowed calls are the job (cost and metric
# reporting), and the denied calls are the paths the role's *old* policy allowed, which
# the reporting code still tries every day. The policy that produces the denials is
# docs/m20-aws-setup.md's ReportingRole policy, and it is what makes this benign.
#
#   ./W10_reporting_role_denials.sh --session-id D09-W10-1 \
#       --role-arn arn:aws:iam::012345678901:role/ReportingRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
[[ -n "$ATH_ROLE_ARN" ]] || ath_die "--role-arn (the ReportingRole to assume) is required"
TODAY="$(date -u +%Y-%m-%d)"
YESTERDAY="$(date -u -d '1 day ago' +%Y-%m-%d 2>/dev/null || date -u -v-1d +%Y-%m-%d)"

# The part of the job the current policy still allows.
ALLOWED=(
  "ce get-cost-and-usage --time-period Start=${YESTERDAY},End=${TODAY} --granularity DAILY --metrics UnblendedCost"
  "cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization --start-time ${YESTERDAY}T00:00:00Z --end-time ${TODAY}T00:00:00Z --period 3600 --statistics Average"
  "sts get-caller-identity"
)

# The part the old policy allowed and the code has not caught up with. Each is a
# different resource type, which is what takes AWS-004 to HIGH (>=5 resource types,
# base.py:108) -- declared in advance, in section 2 of the plan.
DENIED=(
  "ec2 describe-instances"
  "ec2 describe-volumes"
  "s3api list-buckets"
  "iam list-users"
  "iam list-roles"
  "lambda list-functions"
  "logs describe-log-groups"
  "rds describe-db-instances"
  "dynamodb list-tables"
  "sns list-topics"
  "kms list-keys"
  "ssm describe-parameters"
  "cloudformation describe-stacks"
  "elbv2 describe-load-balancers"
)

ath_session_start "W10 reporting job: ${#ALLOWED[@]} permitted calls, ${#DENIED[@]} paths the policy no longer allows"
ath_assume_role "$ATH_ROLE_ARN" "ath-m20-reporting"

for call in "${ALLOWED[@]}"; do
  ath_aws ${call} >/dev/null || echo "  unexpectedly refused: ${call}"
done

# Two passes, because a daily report retries: "retrying the call it cannot make" is the
# quoted false positive this workflow is an instance of. Two passes over 14 calls is
# 28 denials, which is the plan's "~28 denied".
for pass in 1 2; do
  for call in "${DENIED[@]}"; do
    ath_aws_expect_failure "pass ${pass}: ${call}" ${call}
  done
done

ath_session_end done "reporting job ran; the paths outside the narrowed policy were refused as expected"

#!/usr/bin/env bash
# W09 -- Inventory scan: describe-everything across every enabled service, read-only.
# Actor: AssumedRole AuditRole. Plan: ~250 read calls in <10 min, daily at 02:00 UTC.
#   AWS-003 expected to fire, MEDIUM: "Cloud security posture and compliance scanners
#            (the whole point of which is to read every service in the account, on a
#            schedule, forever)"; "Inventory, asset-management, cost-explorer and backup
#            tooling enumerating resources across services as designed."
#   AWS-004 also, if the role lacks some reads.
#
# Read-only by construction: every call below is a list/describe/get. AWS-003's threshold
# is 10 distinct services in 10 minutes (base.py:82) and this touches ~20, on purpose --
# the plan predicts the finding rather than avoiding it.
#
#   ./W09_inventory_scan.sh --session-id D02-W09-1 \
#       --role-arn arn:aws:iam::012345678901:role/AuditRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
[[ -n "$ATH_ROLE_ARN" ]] || ath_die "--role-arn (the AuditRole to assume) is required"

# One line per call: "<service> <operation> [args...]". Read-only, and the file is the
# scan's definition -- an inventory tool's value is that its coverage is a list somebody
# can audit, not a loop nobody can enumerate.
READS=(
  "sts get-caller-identity"
  "ec2 describe-instances"
  "ec2 describe-volumes"
  "ec2 describe-security-groups"
  "ec2 describe-vpcs"
  "ec2 describe-subnets"
  "ec2 describe-snapshots --owner-ids self"
  "ec2 describe-addresses"
  "ec2 describe-key-pairs"
  "ec2 describe-network-interfaces"
  "s3api list-buckets"
  "iam list-users"
  "iam list-roles"
  "iam list-groups"
  "iam list-policies --scope Local"
  "iam get-account-summary"
  "iam list-account-aliases"
  "iam get-account-password-policy"
  "cloudtrail describe-trails"
  "cloudtrail list-trails"
  "cloudwatch describe-alarms"
  "cloudwatch list-metrics --namespace AWS/EC2"
  "logs describe-log-groups"
  "lambda list-functions"
  "ssm describe-instance-information"
  "ssm describe-parameters"
  "cloudformation describe-stacks"
  "cloudformation list-stacks"
  "kms list-keys"
  "kms list-aliases"
  "sns list-topics"
  "sqs list-queues"
  "rds describe-db-instances"
  "dynamodb list-tables"
  "autoscaling describe-auto-scaling-groups"
  "elbv2 describe-load-balancers"
  "route53 list-hosted-zones"
  "config describe-configuration-recorders"
  "events list-rules"
  "budgets describe-budgets --account-id ${ATH_ARG_account_id:-000000000000}"
)

ath_session_start "W09 inventory scan, ${#READS[@]} read calls"
ath_assume_role "$ATH_ROLE_ARN" "ath-m20-audit"

ok=0
denied=0
for call in "${READS[@]}"; do
  # A read the AuditRole is not allowed to make is data, not a failure: the plan says
  # AWS-004 may fire here for exactly that reason. So the loop counts refusals and
  # continues rather than aborting the scan.
  if ath_aws ${call} >/dev/null 2>&1; then
    ok=$((ok + 1))
  else
    denied=$((denied + 1))
    echo "  refused or unavailable: ${call}"
  fi
done

echo "inventory scan: ${ok} succeeded, ${denied} refused or unavailable"
ath_session_end done "inventory scan: ${ok} ok, ${denied} refused/unavailable"

#!/usr/bin/env bash
# W06 -- EC2 lifecycle: run 2 t3.micro, tag, stop, start, terminate.
# Actor: AssumedRole DeveloperRole. Plan: ~25 calls, 4 sessions; "none expected;
# AWS-003 only if bundled with W09".
#
# Modes match the scheduled sessions: launch (day 2), cycle (days 4 and 10),
# terminate (day 14).
#
#   ./W06_ec2_lifecycle.sh --session-id D02-W06-1 --mode launch --ami ami-0abc123 \
#       --role-arn arn:aws:iam::012345678901:role/DeveloperRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
MODE="${ATH_ARG_mode:?--mode must be launch, cycle or terminate}"
TAG="${ATH_ARG_tag:-ath-m20-w06}"
[[ -n "$ATH_ROLE_ARN" ]] || ath_die "--role-arn (the DeveloperRole to assume) is required"

ath_instances() {
  ath_aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=${TAG}" \
              "Name=instance-state-name,Values=pending,running,stopped,stopping" \
    --query "Reservations[].Instances[].InstanceId" --output text
}

ath_session_start "W06 ${MODE}"
ath_assume_role "$ATH_ROLE_ARN" "ath-m20-dev"

case "$MODE" in
  launch)
    AMI="${ATH_ARG_ami:?--ami is required (a current Amazon Linux image for t3.micro)}"
    IDS="$(ath_aws ec2 run-instances --image-id "$AMI" --instance-type t3.micro --count 2 \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${TAG}}]" \
      --query "Instances[].InstanceId" --output text)"
    echo "launched: ${IDS}"
    ath_aws ec2 describe-instances --instance-ids ${IDS} >/dev/null
    ath_aws ec2 create-tags --resources ${IDS} \
      --tags Key=Project,Value=ath-m20 Key=Benign,Value=true
    ath_aws ec2 describe-instance-status --instance-ids ${IDS} >/dev/null || true
    ;;
  cycle)
    IDS="$(ath_instances)"
    [[ -n "$IDS" ]] || ath_die "no ${TAG} instances found; run --mode launch first"
    ath_aws ec2 stop-instances --instance-ids ${IDS} >/dev/null
    ath_aws ec2 describe-instances --instance-ids ${IDS} >/dev/null
    ath_aws ec2 start-instances --instance-ids ${IDS} >/dev/null
    ath_aws ec2 describe-instances --instance-ids ${IDS} >/dev/null
    ;;
  terminate)
    IDS="$(ath_instances)"
    [[ -n "$IDS" ]] || ath_die "no ${TAG} instances found"
    ath_aws ec2 terminate-instances --instance-ids ${IDS} >/dev/null
    ath_aws ec2 describe-instances --instance-ids ${IDS} >/dev/null
    ;;
  *) ath_die "--mode must be launch, cycle or terminate" ;;
esac
ath_session_end done "W06 ${MODE} complete"

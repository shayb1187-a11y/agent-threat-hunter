#!/usr/bin/env bash
# W11 -- Routine service automation: scheduled Lambda (hourly) + one SSM RunCommand/day.
# Actors: AWSService lambda/ssm. Plan: 24+1 per day; "none expected; establishes the
# AWSService background rate".
#
# The hourly half runs without this script. An EventBridge rule created at setup
# (docs/m20-aws-setup.md) invokes the function every hour, and the resulting records carry
# the *service* principal -- which is the point of W11, and is something an operator
# running a script by hand cannot produce. So:
#
#   --mode ssm     the one daily RunCommand, the half that is operator-driven;
#   --mode verify  confirm the hourly rule actually fired (a read of CloudWatch Logs, and
#                  the only way to notice a day where the AWSService background rate is
#                  missing before the corpus is sealed).
#
#   ./W11_service_automation.sh --session-id D02-W11-2 --mode ssm --tag ath-m20-w06
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
MODE="${ATH_ARG_mode:-ssm}"
FUNCTION="${ATH_ARG_function:-ath-m20-heartbeat}"
TAG="${ATH_ARG_tag:-ath-m20-w06}"

ath_session_start "W11 ${MODE}"

case "$MODE" in
  ssm)
    IDS="$(ath_aws ec2 describe-instances \
      --filters "Name=tag:Name,Values=${TAG}" "Name=instance-state-name,Values=running" \
      --query "Reservations[].Instances[].InstanceId" --output text)"
    if [[ -z "$IDS" ]]; then
      ath_session_end skipped "no running ${TAG} instance to target; RunCommand not sent"
      exit 0
    fi
    COMMAND_ID="$(ath_aws ssm send-command --document-name AWS-RunShellScript \
      --instance-ids ${IDS} --comment "ath-m20 daily housekeeping" \
      --parameters "commands=[\"uptime\",\"df -h /\"]" \
      --query "Command.CommandId" --output text)"
    echo "command ${COMMAND_ID}"
    ath_aws ssm list-command-invocations --command-id "$COMMAND_ID" --details >/dev/null || true
    ;;
  verify)
    ath_aws lambda get-function --function-name "$FUNCTION" >/dev/null
    ath_aws logs describe-log-streams --log-group-name "/aws/lambda/${FUNCTION}" \
      --order-by LastEventTime --descending --max-items 3 >/dev/null
    ath_aws events list-rules --name-prefix ath-m20 >/dev/null
    ;;
  *) ath_die "--mode must be ssm or verify" ;;
esac
ath_session_end done "W11 ${MODE} complete"

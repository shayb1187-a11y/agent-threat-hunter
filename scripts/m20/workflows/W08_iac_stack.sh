#!/usr/bin/env bash
# W08 -- IaC: CloudFormation create-stack / delete-stack of a small VPC + SG + instance
# stack, run 4 times. Actors: AssumedRole DeployRole + AWSService cloudformation.
# Plan: ~60 calls/run, 4 runs; "cloudformation, ec2, iam, all classes".
#   AWS-001 "Infrastructure-as-code pipelines that both attach policies and rotate access
#            keys as part of a single automated run."
#   AWS-005 "Infrastructure-as-code runs that delete and recreate identity objects on
#            every apply, so that a no-op change produces a removal."
#   AWS-003 "Infrastructure-as-code planning runs, which read the current state of every
#            resource they manage before deciding what to change."
#
# The plan says "Terraform/CloudFormation"; this uses CloudFormation, so the stack is a
# template file in this directory and needs no extra tool installed. The service-principal
# half of the actor list (AWSService cloudformation) appears in the trail on its own:
# CloudFormation calls ec2 and iam under its own principal while the stack converges.
#
#   ./W08_iac_stack.sh --session-id D04-W08-1 --mode apply --stack ath-m20-stack \
#       --role-arn arn:aws:iam::012345678901:role/DeployRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
MODE="${ATH_ARG_mode:-apply}"
STACK="${ATH_ARG_stack:-ath-m20-stack}"
TEMPLATE="${ATH_ARG_template:-${ATH_WORKFLOWS_DIR}/cloudformation/ath_m20_stack.yaml}"
[[ -n "$ATH_ROLE_ARN" ]] || ath_die "--role-arn (the DeployRole to assume) is required"
[[ -f "$TEMPLATE" ]] || ath_die "template not found: ${TEMPLATE}"

ath_session_start "W08 ${MODE} of ${STACK}"
ath_assume_role "$ATH_ROLE_ARN" "ath-m20-deploy"

# The "planning" reads the plan quotes AWS-003 about: what does the account hold now?
ath_plan_reads() {
  ath_aws cloudformation describe-stacks >/dev/null || true
  ath_aws cloudformation validate-template --template-body "file://${TEMPLATE}" >/dev/null
  ath_aws ec2 describe-vpcs >/dev/null
  ath_aws ec2 describe-subnets >/dev/null
  ath_aws ec2 describe-security-groups >/dev/null
  ath_aws ec2 describe-route-tables >/dev/null
  ath_aws ec2 describe-images --owners amazon --filters "Name=name,Values=al2023-ami-*-x86_64" \
    --query "Images[0].ImageId" --output text >/dev/null
  ath_aws iam list-roles >/dev/null
}

ath_apply() {
  ath_plan_reads
  ath_aws cloudformation create-stack --stack-name "$STACK" \
    --template-body "file://${TEMPLATE}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --tags Key=Project,Value=ath-m20 >/dev/null
  ath_aws cloudformation wait stack-create-complete --stack-name "$STACK"
  ath_aws cloudformation describe-stack-events --stack-name "$STACK" >/dev/null
  ath_aws cloudformation describe-stack-resources --stack-name "$STACK" >/dev/null
}

ath_destroy() {
  ath_aws cloudformation describe-stack-resources --stack-name "$STACK" >/dev/null
  ath_aws cloudformation delete-stack --stack-name "$STACK"
  ath_aws cloudformation wait stack-delete-complete --stack-name "$STACK"
  ath_aws cloudformation describe-stacks >/dev/null || true
}

case "$MODE" in
  apply)   ath_apply ;;
  destroy) ath_destroy ;;
  # One "run" as the plan counts them: apply, then destroy, which is what makes the
  # stack's identity objects be created and removed on every run. Both halves are one
  # session, so the session is started and ended exactly once.
  cycle)   ath_apply; ath_destroy ;;
  *) ath_die "--mode must be apply, destroy or cycle" ;;
esac
ath_session_end done "W08 ${MODE} of ${STACK} complete"

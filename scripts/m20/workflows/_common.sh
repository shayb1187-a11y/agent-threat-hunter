#!/usr/bin/env bash
# Shared helpers for the M20 workflow scripts.
#
# Every workflow script sources this file, and none of them talks to `aws` directly:
# ath_aws() is the only path to the CLI, which is what makes the two guarantees below
# enforceable rather than aspirational.
#
# 1. AWS-002 is never exercised. The plan (section 2) says "stopping the trail would
#    delete the corpus. Its expected count is zero and that is a prediction, not an
#    omission." ath_refuse_forbidden() refuses the calls that would break that
#    prediction, so a copy-pasted command cannot quietly destroy the corpus.
# 2. Every session's start and end lands in sessions.csv. ath_session_start/end call
#    scripts/m20/sessions.py record, which is append-only; an ERR trap records a failed
#    session rather than leaving a session that started and never ended.
#
# Usage inside a workflow script:
#
#     source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
#     ath_parse_args "$@"
#     ath_session_start "W06 session 1: launch two t3.micro"
#     ath_aws ec2 run-instances ...
#     ath_session_end done

set -euo pipefail

ATH_WORKFLOWS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATH_REPO_ROOT="$(cd "${ATH_WORKFLOWS_DIR}/../../.." && pwd)"
ATH_SESSIONS_PY="${ATH_REPO_ROOT}/scripts/m20/sessions.py"
ATH_PYTHON="${ATH_PYTHON:-python}"
ATH_SESSIONS_CSV="${ATH_SESSIONS_CSV:-${ATH_REPO_ROOT}/reports/m20/sessions.csv}"
ATH_PROFILE="${ATH_PROFILE:-ath-m20}"
ATH_REGION="${ATH_REGION:-us-east-1}"
ATH_DRY_RUN="${ATH_DRY_RUN:-0}"
ATH_SESSION_ID=""
ATH_ROLE_ARN=""
ATH_ASSUMED=""
ATH_STARTED=0

ath_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

ath_die() { echo "ERROR: $*" >&2; exit 2; }

ath_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --session-id) ATH_SESSION_ID="$2"; shift 2 ;;
      --profile)    ATH_PROFILE="$2";    shift 2 ;;
      --region)     ATH_REGION="$2";     shift 2 ;;
      --sessions)   ATH_SESSIONS_CSV="$2"; shift 2 ;;
      --role-arn)   ATH_ROLE_ARN="$2";   shift 2 ;;
      --dry-run)    ATH_DRY_RUN=1;       shift 1 ;;
      --help|-h)    sed -n '2,30p' "$0"; exit 0 ;;
      --*)
        key="${1#--}"; key="${key//-/_}"
        [[ $# -ge 2 ]] || ath_die "$1 needs a value"
        printf -v "ATH_ARG_${key}" '%s' "$2"; shift 2 ;;
      *) ath_die "unexpected argument: $1" ;;
    esac
  done
  [[ -n "$ATH_SESSION_ID" ]] || ath_die "--session-id is required; it must be a session id from sessions.csv"
}

# Refuse anything that would stop or delete the trail, or narrow what it records.
# Exercising AWS-002 is the one action the plan rules out absolutely.
ath_refuse_forbidden() {
  local joined="$*"
  case "$joined" in
    *"stop-logging"*|*"delete-trail"*|*"update-trail"*|*"put-event-selectors"*|*"delete-bucket-policy"*)
      echo "REFUSED: '${joined}' would stop, delete or narrow the trail." >&2
      echo "The plan (section 2) declares AWS-002 is never exercised and predicts zero" >&2
      echo "findings for it; and section 3's trail is where the corpus comes from." >&2
      exit 3 ;;
  esac
}

ath_aws() {
  ath_refuse_forbidden "$@"
  if [[ "$ATH_DRY_RUN" == "1" ]]; then
    echo "DRY-RUN aws $*"
    return 0
  fi
  if [[ -n "$ATH_ASSUMED" ]]; then
    aws --region "$ATH_REGION" "$@"
  else
    aws --profile "$ATH_PROFILE" --region "$ATH_REGION" "$@"
  fi
}

# A call the workflow expects the platform to refuse (W10) or reject (W12). The denial
# is the data, so a non-zero exit must not abort the session.
ath_aws_expect_failure() {
  local label="$1"; shift
  if ath_aws "$@" >/dev/null 2>&1; then
    echo "  unexpected SUCCESS: ${label}"
  else
    echo "  expected refusal: ${label}"
  fi
}

# Assume a role and keep using it for the rest of the script. The session name is what
# CloudTrail records as the principal, and sessions.csv's actor_arn quotes it, so the
# two must agree -- see scripts/m20/sessions.py ACTORS.
ath_assume_role() {
  local role_arn="$1" session_name="$2"
  if [[ "$ATH_DRY_RUN" == "1" ]]; then
    echo "DRY-RUN assume-role ${role_arn} as ${session_name}"
    ATH_ASSUMED="dry-run"
    return 0
  fi
  local creds
  creds="$(aws sts assume-role --role-arn "$role_arn" --role-session-name "$session_name" \
    --profile "$ATH_PROFILE" --region "$ATH_REGION" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)"
  AWS_ACCESS_KEY_ID="$(echo "$creds" | cut -f1)"
  AWS_SECRET_ACCESS_KEY="$(echo "$creds" | cut -f2)"
  AWS_SESSION_TOKEN="$(echo "$creds" | cut -f3)"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  ATH_ASSUMED="$session_name"
}

ath_record() {
  "$ATH_PYTHON" "$ATH_SESSIONS_PY" record --sessions "$ATH_SESSIONS_CSV" \
    --session-id "$ATH_SESSION_ID" "$@"
}

ath_session_start() {
  local note="${1:-}"
  ath_record --actual-start "$(ath_now)" --status in_progress --notes "$note"
  ATH_STARTED=1
  trap 'ath_on_error' ERR
}

ath_session_end() {
  local status="${1:-done}" note="${2:-}"
  trap - ERR
  ATH_STARTED=0
  if [[ -n "$note" ]]; then
    ath_record --actual-end "$(ath_now)" --status "$status" --notes "$note"
  else
    ath_record --actual-end "$(ath_now)" --status "$status"
  fi
}

ath_on_error() {
  local code=$?
  trap - ERR
  if [[ "$ATH_STARTED" == "1" ]]; then
    ATH_STARTED=0
    ath_record --actual-end "$(ath_now)" --status failed \
      --notes "script exited ${code}; see the operator log" || true
  fi
  exit "$code"
}

# A prompt for the steps only a human in a browser can perform (console login).
ath_manual_step() {
  echo
  echo "OPERATOR: $*"
  if [[ "$ATH_DRY_RUN" == "1" ]]; then
    echo "  (dry run: not waiting)"
    return 0
  fi
  read -r -p "  press Enter when done " _ack
}

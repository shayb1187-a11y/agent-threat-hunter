#!/usr/bin/env bash
# W07 -- S3 operations: create bucket, put/get/list objects, lifecycle policy, delete bucket.
# Actor: AssumedRole DeveloperRole. Plan: ~40 calls, 5 sessions; "none expected
# (object-level events are not enabled -- see section 3)".
#
# Object-level calls (PutObject/GetObject) produce NO CloudTrail records here: section 3
# enables management events only. They are still performed, because the workflow is meant
# to be ordinary work rather than a list of loggable calls -- what the trail records is
# the bucket-level management around them.
#
# Modes match the scheduled sessions: create (day 3, session 1), objects (day 3 session 2
# and day 5), lifecycle (day 10), delete (day 14).
#
#   ./W07_s3_operations.sh --session-id D03-W07-1 --mode create --bucket ath-m20-work-0001 \
#       --role-arn arn:aws:iam::012345678901:role/DeveloperRole
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
ath_parse_args "$@"
MODE="${ATH_ARG_mode:?--mode must be create, objects, lifecycle or delete}"
BUCKET="${ATH_ARG_bucket:?--bucket is required}"
[[ -n "$ATH_ROLE_ARN" ]] || ath_die "--role-arn (the DeveloperRole to assume) is required"

ath_session_start "W07 ${MODE} on ${BUCKET}"
ath_assume_role "$ATH_ROLE_ARN" "ath-m20-dev"

case "$MODE" in
  create)
    ath_aws s3api create-bucket --bucket "$BUCKET" >/dev/null
    ath_aws s3api put-public-access-block --bucket "$BUCKET" \
      --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ath_aws s3api put-bucket-versioning --bucket "$BUCKET" \
      --versioning-configuration "Status=Enabled"
    ath_aws s3api get-bucket-location --bucket "$BUCKET" >/dev/null
    ath_aws s3api list-buckets >/dev/null
    ;;
  objects)
    WORKDIR="$(mktemp -d)"
    printf 'ath m20 benign object %s\n' "$(ath_now)" > "${WORKDIR}/note.txt"
    for n in 1 2 3 4 5; do
      ath_aws s3api put-object --bucket "$BUCKET" --key "work/note-${n}.txt" \
        --body "${WORKDIR}/note.txt" >/dev/null
    done
    ath_aws s3api list-objects-v2 --bucket "$BUCKET" --prefix work/ >/dev/null
    ath_aws s3api get-object --bucket "$BUCKET" --key work/note-1.txt \
      "${WORKDIR}/downloaded.txt" >/dev/null
    ath_aws s3api head-object --bucket "$BUCKET" --key work/note-1.txt >/dev/null
    rm -rf "$WORKDIR"
    ;;
  lifecycle)
    ath_aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
      --lifecycle-configuration "file://${ATH_WORKFLOWS_DIR}/policies/w07_lifecycle.json"
    ath_aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" >/dev/null
    ath_aws s3api get-bucket-tagging --bucket "$BUCKET" >/dev/null
    ;;
  delete)
    # Teardown of the work bucket only. The *trail* bucket is never touched: deleting it
    # would destroy the corpus, which is the same reason AWS-002 is never exercised.
    case "$BUCKET" in
      *trail*) ath_die "refusing to delete ${BUCKET}: that name looks like the trail bucket" ;;
    esac
    ath_aws s3 rm "s3://${BUCKET}" --recursive >/dev/null
    ath_aws s3api delete-bucket-lifecycle --bucket "$BUCKET" || true
    ath_aws s3api delete-bucket --bucket "$BUCKET"
    ;;
  *) ath_die "--mode must be create, objects, lifecycle or delete" ;;
esac
ath_session_end done "W07 ${MODE} complete"

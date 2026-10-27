#!/usr/bin/env bash
# Purpose: Preview or add inbound all-protocol IPv4 denies to an existing AWS
# Network ACL from ../config/aws-nacl-blocked-ip-rules.json.
# Usage (from the repository root):
#   bash scripts/apply-aws-nacl-denies.sh acl-0123456789abcdef0
#   bash scripts/apply-aws-nacl-denies.sh acl-0123456789abcdef0 --apply
# The first command only reads AWS state. --apply changes real network rules.
#
# Requirements: Bash, jq, AWS CLI v2, network access to AWS APIs, and configured
# credentials/profile and Region for the intended account. IAM must allow
# ec2:DescribeNetworkAcls and, for apply, ec2:CreateNetworkAclEntry. Keep the
# script/config directory layout intact. No EC2 SSH access or load balancer is
# required; this can run from a trusted administrator machine.
#
# Review every associated subnet: NACL changes affect all their resources.
# Confirm sufficient APPROVED inbound quota (not just the maximum checked here),
# unused rule numbers, and denies before allows. Preserve existing inbound and
# outbound rules; NACLs are stateless. Verify actual source IPs behind proxies.
# Entries are added one at a time; failure can leave a partial update, with no
# automatic rollback. Inspect AWS before retrying. Never store credentials here.
set -euo pipefail

RULES_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config/aws-nacl-blocked-ip-rules.json"
NACL_ID="${1:-}"
MODE="${2:-}"

if [[ ! "$NACL_ID" =~ ^acl-[A-Za-z0-9]+$ ]]; then
  echo "Usage: $0 acl-xxxxxxxx [--apply]" >&2
  exit 2
fi
if [[ -n "$MODE" && "$MODE" != "--apply" ]]; then
  echo "Only the optional --apply argument is supported." >&2
  exit 2
fi
command -v aws >/dev/null 2>&1 || { echo "AWS CLI is required." >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required." >&2; exit 1; }

if ! jq -e '.Rules | type == "array" and length > 0' "$RULES_FILE" >/dev/null; then
  echo "Populate $RULES_FILE with reviewed deny rules before running this helper." >&2
  exit 1
fi

ACL_JSON="$(aws ec2 describe-network-acls --network-acl-ids "$NACL_ID" --output json)"
ACL_COUNT="$(jq '.NetworkAcls | length' <<<"$ACL_JSON")"
if [[ "$ACL_COUNT" != "1" ]]; then
  echo "Expected exactly one Network ACL for $NACL_ID; found $ACL_COUNT." >&2
  exit 1
fi

VPC_ID="$(jq -r '.NetworkAcls[0].VpcId' <<<"$ACL_JSON")"
SUBNETS="$(jq -r '[.NetworkAcls[0].Associations[].SubnetId] | join(", ")' <<<"$ACL_JSON")"
CURRENT_RULES="$(jq '[.NetworkAcls[0].Entries[] | select(.Egress == false and (.RuleNumber | tostring) != "*" and (.RuleNumber | tonumber) < 32767)] | length' <<<"$ACL_JSON")"
RULE_COUNT="$(jq '.Rules | length' "$RULES_FILE")"
TOTAL_RULES=$((CURRENT_RULES + RULE_COUNT))
if (( TOTAL_RULES > 40 )); then
  echo "Cannot fit these rules: $CURRENT_RULES existing inbound rules + $RULE_COUNT new rules = $TOTAL_RULES, above the AWS maximum quota of 40." >&2
  exit 1
fi

if jq -e --slurpfile planned "$RULES_FILE" '
  [.NetworkAcls[0].Entries[] | select(.Egress == false and (.RuleNumber | tostring) != "*") | .RuleNumber] as $existing |
  any($planned[0].Rules[]; .RuleNumber as $number | $existing | index($number) != null)
' <<<"$ACL_JSON" >/dev/null; then
  echo "One or more planned rule numbers are already in use. Review the ACL and edit the rule numbers in $RULES_FILE before retrying." >&2
  exit 1
fi

if jq -e --slurpfile planned "$RULES_FILE" '
  [.NetworkAcls[0].Entries[] | select(.Egress == false and .RuleAction == "allow") | .RuleNumber] as $allowRules |
  ($planned[0].Rules | map(.RuleNumber) | max) as $lastDeny |
  any($allowRules[]; . < $lastDeny)
' <<<"$ACL_JSON" >/dev/null; then
  echo "An existing inbound ALLOW rule precedes the planned deny rules. The deny rules could be bypassed; adjust rule order carefully before applying." >&2
  exit 1
fi

cat <<EOF_REPORT
NACL: $NACL_ID
VPC: $VPC_ID
Associated subnets: ${SUBNETS:-none}
Existing inbound entries: $CURRENT_RULES
New inbound deny entries: $RULE_COUNT
Total after change: $TOTAL_RULES (AWS maximum quota: 40)
EOF_REPORT
jq -r '.Rules[] | "  rule \(.RuleNumber): deny \(.CidrBlock) (all protocols/ports)"' "$RULES_FILE"

if [[ "$MODE" != "--apply" ]]; then
  cat <<'EOF_DRYRUN'

DRY RUN ONLY: no AWS changes were made.
Inspect the associated subnets and existing rules. To apply, run this script
again with --apply and the same NACL ID. Check the VPC Network ACL quota in
Service Quotas; AWS's default is 20 entries per direction, adjustable up to 40.
EOF_DRYRUN
  exit 0
fi

while IFS=$'\t' read -r RULE_NUMBER CIDR; do
  aws ec2 create-network-acl-entry \
    --network-acl-id "$NACL_ID" \
    --rule-number "$RULE_NUMBER" \
    --protocol -1 \
    --rule-action deny \
    --no-egress \
    --cidr-block "$CIDR" \
    --output json >/dev/null
  echo "Added inbound deny rule $RULE_NUMBER for $CIDR"
done < <(jq -r '.Rules[] | [.RuleNumber, .CidrBlock] | @tsv' "$RULES_FILE")

echo "Applied all $RULE_COUNT inbound deny rules. Verify the ACL entries and test from an allowed source."

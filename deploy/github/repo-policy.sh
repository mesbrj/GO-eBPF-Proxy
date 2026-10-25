#!/usr/bin/env bash
# Repository policy as code (AD-024 to AD-027): the ruleset on main, kept in
# .github/rulesets/main.json, and the repository settings below.
#
#   repo-policy.sh check   compare the live repository with the committed policy
#   repo-policy.sh apply   write the committed policy, then compare as check does
#
# check prints one line per setting, "ok <name>" or "want <value> got <value>
# for <name>", and exits 0 when every setting matches, 1 otherwise. apply exits
# with check's code, so a partial apply exits 1 naming what still differs.
# Anything else prints this usage and exits 2.
#
# Needs gh, authenticated as an administrator of the repository, and jq.
# REPO overrides the repository (default mesbrj/GO-eBPF-Proxy).
set -uo pipefail

REPO="${REPO:-mesbrj/GO-eBPF-Proxy}"
RULESET_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.github/rulesets/main.json"
readonly REPO RULESET_FILE

# The committed settings. Each is written by one call in apply and read back in
# check; review-bot's main deployment branch policy is created only when absent.
readonly ALLOW_MERGE_COMMIT=false
readonly ALLOW_REBASE_MERGE=true
readonly ALLOW_SQUASH_MERGE=true
readonly PULL_REQUEST_CREATION_POLICY=collaborators_only
readonly FORK_PR_APPROVAL_POLICY=all_external_contributors
readonly DEFAULT_WORKFLOW_PERMISSIONS=read
readonly CAN_APPROVE_PULL_REQUEST_REVIEWS=false
readonly SHA_PINNING_REQUIRED=true
readonly VULNERABILITY_ALERTS=enabled
readonly AUTOMATED_SECURITY_FIXES=enabled
# Door 11: review-bot admits deployments from the branch main only.
readonly REVIEW_BOT_DEPLOYMENT_BRANCHES="custom branch:main"

usage() {
  {
    echo "usage: repo-policy.sh check|apply"
    echo
    sed -n '2,15s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"
  } >&2
}

# The ruleset as compared: without the fields the server assigns, keys sorted,
# rules in type order. main.json also states the two pull_request parameters
# GitHub adds on its own, required_reviewers and the undocumented
# require_extra_approval_for_unattributed_changes, so the comparison covers the
# whole rule set GitHub enforces.
normalize_ruleset() {
  jq -cS 'del(.id, .node_id, ._links, .created_at, .updated_at, .source, .source_type, .current_user_can_bypass)
    | .rules |= sort_by(.type)'
}

# Prints the id of the live ruleset named as in main.json, or nothing when
# there is none; fails when the rulesets cannot be listed.
ruleset_id() {
  local name
  name=$(jq -r .name "$RULESET_FILE") || return 1
  gh api "repos/$REPO/rulesets" | jq -r --arg name "$name" 'map(select(.name == $name)) | first | .id // empty'
}

live_ruleset() {
  local id
  if ! id=$(ruleset_id); then
    echo unreadable
  elif [[ -z "$id" ]]; then
    echo absent
  else
    gh api "repos/$REPO/rulesets/$id" | normalize_ruleset || echo unreadable
  fi
}

vulnerability_alerts() {
  local err
  if err=$(gh api "repos/$REPO/vulnerability-alerts" --silent 2>&1); then
    echo enabled
  elif [[ "$err" == *"HTTP 404"* ]]; then
    echo disabled
  else
    echo unreadable
  fi
}

# Prints review-bot's deployment branch rule: "custom" and its sorted
# type:name policies when only custom branch policies are on, "protected" for
# any other rule, "none" when there is no rule, or "unreadable".
review_bot_deployment_branches() {
  local env policies
  env=$(gh api "repos/$REPO/environments/review-bot") || { echo unreadable; return; }
  case "$(jq -r 'if .deployment_branch_policy == null then "none" elif .deployment_branch_policy.custom_branch_policies and (.deployment_branch_policy.protected_branches | not) then "custom" else "protected" end' <<<"$env")" in
  custom)
    policies=$(gh api "repos/$REPO/environments/review-bot/deployment-branch-policies") || { echo unreadable; return; }
    echo "custom $(jq -r '[.branch_policies[] | "\(.type):\(.name)"] | sort | join(",")' <<<"$policies")"
    ;;
  protected) echo protected ;;
  *) echo none ;;
  esac
}

# compare <name> <want> <got>
compare() {
  if [[ "$2" == "$3" ]]; then
    echo "ok $1"
    return 0
  fi
  echo "want $2 got $3 for $1"
  return 1
}

check() {
  local repo actions workflow fork fixes status=0
  repo=$(gh api "repos/$REPO") || repo='{}'
  actions=$(gh api "repos/$REPO/actions/permissions") || actions='{}'
  workflow=$(gh api "repos/$REPO/actions/permissions/workflow") || workflow='{}'
  fork=$(gh api "repos/$REPO/actions/permissions/fork-pr-contributor-approval") || fork='{}'
  fixes=$(gh api "repos/$REPO/automated-security-fixes" | jq -r 'if .enabled then "enabled" else "disabled" end') || fixes=disabled

  compare ruleset "$(normalize_ruleset <"$RULESET_FILE")" "$(live_ruleset)" || status=1
  compare allow_merge_commit "$ALLOW_MERGE_COMMIT" "$(jq -r .allow_merge_commit <<<"$repo")" || status=1
  compare allow_rebase_merge "$ALLOW_REBASE_MERGE" "$(jq -r .allow_rebase_merge <<<"$repo")" || status=1
  compare allow_squash_merge "$ALLOW_SQUASH_MERGE" "$(jq -r .allow_squash_merge <<<"$repo")" || status=1
  compare pull_request_creation_policy "$PULL_REQUEST_CREATION_POLICY" "$(jq -r .pull_request_creation_policy <<<"$repo")" || status=1
  compare fork_pr_approval_policy "$FORK_PR_APPROVAL_POLICY" "$(jq -r .approval_policy <<<"$fork")" || status=1
  compare default_workflow_permissions "$DEFAULT_WORKFLOW_PERMISSIONS" "$(jq -r .default_workflow_permissions <<<"$workflow")" || status=1
  compare can_approve_pull_request_reviews "$CAN_APPROVE_PULL_REQUEST_REVIEWS" "$(jq -r .can_approve_pull_request_reviews <<<"$workflow")" || status=1
  compare sha_pinning_required "$SHA_PINNING_REQUIRED" "$(jq -r .sha_pinning_required <<<"$actions")" || status=1
  compare vulnerability_alerts "$VULNERABILITY_ALERTS" "$(vulnerability_alerts)" || status=1
  compare automated_security_fixes "$AUTOMATED_SECURITY_FIXES" "$fixes" || status=1
  compare review_bot_deployment_branches "$REVIEW_BOT_DEPLOYMENT_BRANCHES" "$(review_bot_deployment_branches)" || status=1
  return "$status"
}

# write <gh api arguments>: a failed write is reported and left for check to name.
write() {
  gh api "$@" >/dev/null || echo "repo-policy: write failed: gh api $*" >&2
}

apply() {
  local id policies
  write -X PATCH "repos/$REPO" -F allow_merge_commit="$ALLOW_MERGE_COMMIT"
  write -X PATCH "repos/$REPO" -F allow_rebase_merge="$ALLOW_REBASE_MERGE"
  write -X PATCH "repos/$REPO" -F allow_squash_merge="$ALLOW_SQUASH_MERGE"
  write -X PATCH "repos/$REPO" -f pull_request_creation_policy="$PULL_REQUEST_CREATION_POLICY"
  write -X PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" -f approval_policy="$FORK_PR_APPROVAL_POLICY"
  write -X PUT "repos/$REPO/actions/permissions/workflow" -f default_workflow_permissions="$DEFAULT_WORKFLOW_PERMISSIONS"
  write -X PUT "repos/$REPO/actions/permissions/workflow" -F can_approve_pull_request_reviews="$CAN_APPROVE_PULL_REQUEST_REVIEWS"
  # enabled is required by this endpoint; Actions is already on.
  write -X PUT "repos/$REPO/actions/permissions" -F enabled=true -F sha_pinning_required="$SHA_PINNING_REQUIRED"
  write -X PUT "repos/$REPO/vulnerability-alerts"
  write -X PUT "repos/$REPO/automated-security-fixes"
  if ! id=$(ruleset_id); then
    echo "repo-policy: cannot list rulesets; ruleset not written" >&2
  elif [[ -n "$id" ]]; then
    write -X PUT "repos/$REPO/rulesets/$id" --input "$RULESET_FILE"
  else
    write -X POST "repos/$REPO/rulesets" --input "$RULESET_FILE"
  fi
  # Read before writing, so that after the last write come check's reads only.
  # GitHub answers 404 while custom branch policies are not enabled: no policy yet.
  if ! policies=$(gh api "repos/$REPO/environments/review-bot/deployment-branch-policies" 2>&1); then
    if [[ "$policies" == *"HTTP 404"* ]]; then
      policies='{"branch_policies":[]}'
    else
      policies=unreadable
    fi
  fi
  write -X PUT "repos/$REPO/environments/review-bot" \
    -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
  if [[ "$policies" == unreadable ]]; then
    echo "repo-policy: cannot list review-bot's deployment branch policies; main not added" >&2
  elif ! jq -e 'any(.branch_policies[]; .type == "branch" and .name == "main")' <<<"$policies" >/dev/null; then
    write -X POST "repos/$REPO/environments/review-bot/deployment-branch-policies" -f name=main -f type=branch
  fi
  check
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi
case "$1" in
check) check ;;
apply) apply ;;
*)
  usage
  exit 2
  ;;
esac

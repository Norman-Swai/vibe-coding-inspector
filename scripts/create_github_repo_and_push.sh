#!/usr/bin/env bash
set -euo pipefail

# Usage examples:
#   GITHUB_TOKEN=ghp_xxx ./scripts/create_github_repo_and_push.sh \
#     --repo-name vibe-coding-inspector \
#     --visibility public \
#     --message "Initial commit"
#
#   GITHUB_TOKEN=ghp_xxx ./scripts/create_github_repo_and_push.sh \
#     --repo-name vibe-coding-inspector \
#     --visibility private \
#     --description "Vibe Coding Inspector"

REPO_NAME=""
VISIBILITY="private"
DESCRIPTION=""
COMMIT_MESSAGE="Initial commit"
DEFAULT_BRANCH="main"
REMOTE_NAME="origin"
SKIP_COMMIT="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-name)
      REPO_NAME="$2"
      shift 2
      ;;
    --visibility)
      VISIBILITY="$2"
      shift 2
      ;;
    --description)
      DESCRIPTION="$2"
      shift 2
      ;;
    --message)
      COMMIT_MESSAGE="$2"
      shift 2
      ;;
    --default-branch)
      DEFAULT_BRANCH="$2"
      shift 2
      ;;
    --remote-name)
      REMOTE_NAME="$2"
      shift 2
      ;;
    --skip-commit)
      SKIP_COMMIT="true"
      shift 1
      ;;
    -h|--help)
      sed -n '1,40p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$REPO_NAME" ]]; then
  echo "Error: --repo-name is required." >&2
  exit 1
fi

if [[ "$VISIBILITY" != "public" && "$VISIBILITY" != "private" ]]; then
  echo "Error: --visibility must be 'public' or 'private'." >&2
  exit 1
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Error: set GITHUB_TOKEN with repo creation permissions before running this script." >&2
  exit 1
fi

if ! git config user.name >/dev/null 2>&1; then
  echo "Error: git user.name is not configured." >&2
  exit 1
fi

if ! git config user.email >/dev/null 2>&1; then
  echo "Error: git user.email is not configured." >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Initializing git repository..."
  git init
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)"
if [[ "$CURRENT_BRANCH" == "HEAD" || "$CURRENT_BRANCH" == "master" ]]; then
  git branch -M "$DEFAULT_BRANCH"
elif [[ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ]]; then
  git branch -M "$DEFAULT_BRANCH"
fi

if [[ "$SKIP_COMMIT" != "true" ]]; then
  echo "Staging files..."
  git add .

  if ! git diff --cached --quiet; then
    echo "Creating commit..."
    git commit -m "$COMMIT_MESSAGE"
  else
    echo "No staged changes to commit; continuing."
  fi
fi

OWNER_JSON="$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" https://api.github.com/user)"
OWNER_LOGIN="$(printf '%s' "$OWNER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["login"])')"

REPO_API_PAYLOAD="$(python3 - <<PY
import json
print(json.dumps({
    "name": ${REPO_NAME@Q},
    "description": ${DESCRIPTION@Q},
    "private": ${VISIBILITY@Q} == "private",
    "auto_init": False,
}))
PY
)"

echo "Creating GitHub repository ${OWNER_LOGIN}/${REPO_NAME}..."
CREATE_RESPONSE_FILE="$(mktemp)"
HTTP_CODE="$(curl -sS -o "$CREATE_RESPONSE_FILE" -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user/repos \
  -d "$REPO_API_PAYLOAD")"

if [[ "$HTTP_CODE" != "201" && "$HTTP_CODE" != "422" ]]; then
  echo "GitHub API error (HTTP $HTTP_CODE):" >&2
  cat "$CREATE_RESPONSE_FILE" >&2
  rm -f "$CREATE_RESPONSE_FILE"
  exit 1
fi

if [[ "$HTTP_CODE" == "422" ]]; then
  echo "Repository may already exist; continuing with remote setup."
fi
rm -f "$CREATE_RESPONSE_FILE"

REMOTE_URL="https://github.com/${OWNER_LOGIN}/${REPO_NAME}.git"

if git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
  git remote set-url "$REMOTE_NAME" "$REMOTE_URL"
else
  git remote add "$REMOTE_NAME" "$REMOTE_URL"
fi

echo "Pushing to ${REMOTE_URL}..."
git push -u "$REMOTE_NAME" "$DEFAULT_BRANCH"

echo "Done. Repository available at: ${REMOTE_URL}"

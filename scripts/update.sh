#!/bin/bash -eu

TARGET=$1
COMMIT_MSG=$2

if [ -z "$TARGET" ]; then
  echo "target required"
  exit 1
fi

if [ -z "$COMMIT_MSG" ]; then
  echo "commit message required"
  exit 1
fi

result=0
./vuln-list-update -vuln-list-dir "$VULN_LIST_DIR" -target "$TARGET" || result=$?

if [ $result -ne 0 ]; then
  echo "[Err] Revert changes" >&2
  cd "$VULN_LIST_DIR" && git reset --hard HEAD
  exit 1
fi

cd "$VULN_LIST_DIR" || exit 1

# Optional: space-separated paths under this repo to stage (e.g. "cvrf/suse-cves" for
# huge SUSE CVE runs). Avoids "git add ." over the whole vuln-list tree when only one
# subtree changed, which is much faster and uses less memory on CI.
git_has_changes() {
  if [[ -n "${VULN_LIST_GIT_ADD_PATHS:-}" ]]; then
    local p
    for p in ${VULN_LIST_GIT_ADD_PATHS}; do
      if [[ -n $(git status --porcelain -- "$p" 2>/dev/null) ]]; then
        return 0
      fi
    done
    return 1
  fi
  [[ -n $(git status --porcelain) ]]
}

git_stage_changes() {
  if [[ -n "${VULN_LIST_GIT_ADD_PATHS:-}" ]]; then
    local p
    for p in ${VULN_LIST_GIT_ADD_PATHS}; do
      git add -- "$p"
    done
  else
    git add .
  fi
}

if git_has_changes; then
  # Large single-target pushes (many JSON files) can need a bigger HTTP buffer.
  git config http.postBuffer 524288000 || true
  git_stage_changes
  git commit -m "${COMMIT_MSG}"
  git push
fi

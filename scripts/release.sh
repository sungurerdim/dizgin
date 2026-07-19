#!/usr/bin/env bash
# DIZGIN release orchestrator — the body of `make release [TAG=vX.Y.Z]`.
# See CONTRIBUTING.md "Cutting a Release" for the human-facing walkthrough.
#
# Sequence (each stage stops the whole chain on failure — nothing partial
# ever reaches the deploy stage, let alone origin/GitHub):
#   1. dirty-tree guard      — only a committed HEAD is ever released.
#   2. gate, exactly once    — resolve the version (explicit TAG, or
#                              auto-detected from Conventional Commits since
#                              the last release tag; a brand-new auto-detected
#                              version is shown with its commit list + diffstat
#                              and requires an explicit yes — RELEASE_YES=1 to
#                              skip — before a tag is ever created), then
#                              `git push` (the pre-push hook runs the full
#                              lint+build+test+vuln+e2e set) when there is
#                              something new to push; otherwise the same
#                              gate script runs inline, since the hook would
#                              not fire on a no-op push (retry/resume case).
#   3. cadence-aware heavy layer — coverage threshold + full cross-platform
#                              artifact build, skipped if it ran in the last
#                              7 days (tracked by a gitignored stamp file),
#                              otherwise required to pass before deploy.
#   4. deploy                — goreleaser publishes to GitHub Releases.
#   5. verify-live            — the published tag/commit/assets are checked
#                              against local HEAD; deploy is not considered
#                              done until this is green.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION_ARG="${1:-}"

REPO_SLUG=$(git remote get-url origin | sed -E 's#(git@|https://)github\.com[:/]##; s#\.git$##')
STAMP=".release-heavy-stamp"
COVERAGE_THRESHOLD=70

echo "==> [1/5] dirty-tree guard"
if [[ -n "$(git status --porcelain)" ]]; then
  echo "release: working tree is not clean — only a committed HEAD is released." >&2
  git status --porcelain >&2
  exit 1
fi

echo "==> [2/5] gate, exactly once"
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "${BRANCH}" == "HEAD" ]]; then
  echo "release: detached HEAD — checkout a branch before releasing." >&2
  exit 1
fi

if [[ -n "${VERSION_ARG}" ]]; then
  if ! [[ "${VERSION_ARG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "release: '${VERSION_ARG}' is not a semver tag. Expected e.g. v0.2.0 or v0.2.0-rc1." >&2
    exit 1
  fi
  VERSION="${VERSION_ARG}"
  echo "release: using explicit tag ${VERSION}"
else
  # Auto-detect from Conventional Commits since the last pure-semver release
  # tag (pre-release tags like v0.2.0-rc1 are excluded from this baseline —
  # pass TAG= explicitly to cut a pre-release). No prior tag -> bootstrap.
  LAST_TAG=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname 2>/dev/null \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
  if [[ -z "${LAST_TAG}" ]]; then
    VERSION="v0.1.0"
    echo "release: no prior release tag found — bootstrapping at ${VERSION}."
  else
    COMMITS_SINCE=$(git rev-list --count "${LAST_TAG}..HEAD")
    if [[ "${COMMITS_SINCE}" -eq 0 ]]; then
      echo "release: no commits since ${LAST_TAG} — nothing to release." >&2
      exit 1
    fi
    BUMP="none"
    while IFS= read -r subject; do
      if [[ "${subject}" =~ ^[a-zA-Z]+(\([^\)]*\))?!: ]]; then
        BUMP="major"
      elif [[ "${subject}" =~ ^feat(\([^\)]*\))?: ]] && [[ "${BUMP}" != "major" ]]; then
        BUMP="minor"
      elif [[ "${subject}" =~ ^fix(\([^\)]*\))?: ]] && [[ "${BUMP}" != "major" && "${BUMP}" != "minor" ]]; then
        BUMP="patch"
      fi
    done < <(git log "${LAST_TAG}..HEAD" --format=%s)
    if [[ "${BUMP}" != "major" ]] && git log "${LAST_TAG}..HEAD" --format=%B | grep -qE '^BREAKING[- ]CHANGE:'; then
      BUMP="major"
    fi
    if [[ "${BUMP}" == "none" ]]; then
      echo "release: no feat/fix/breaking commits since ${LAST_TAG} (only chore/docs/refactor/test/ci/style) — nothing to release." >&2
      echo "release: pass an explicit tag to release anyway: make release TAG=vX.Y.Z" >&2
      exit 1
    fi
    IFS='.' read -r MAJOR MINOR PATCH <<< "${LAST_TAG#v}"
    case "${BUMP}" in
      major) MAJOR=$((MAJOR+1)); MINOR=0; PATCH=0 ;;
      minor) MINOR=$((MINOR+1)); PATCH=0 ;;
      patch) PATCH=$((PATCH+1)) ;;
    esac
    VERSION="v${MAJOR}.${MINOR}.${PATCH}"
    echo "release: auto-detected ${VERSION} (bump=${BUMP}, since ${LAST_TAG})"
  fi
fi

TAG_EXISTS_LOCALLY=0
if git rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null; then
  TAG_EXISTS_LOCALLY=1
fi

# Confirmation summary — only for a brand-new auto-detected version (not an
# explicit TAG=, which is already a deliberate choice; not a resume of an
# already-tagged attempt, which was already confirmed once). This is the
# safety net against shipping a minor/major release for a trivially small
# change that just happened to carry a feat:/fix: prefix: show exactly what
# is about to go out and require an explicit yes, rather than guessing from
# an arbitrary line-count threshold that would as easily block a genuinely
# release-worthy one-line fix.
if [[ -z "${VERSION_ARG}" && "${TAG_EXISTS_LOCALLY}" -eq 0 ]]; then
  echo ""
  echo "release: about to auto-release ${VERSION} (bump=${BUMP:-initial})"
  if [[ -n "${LAST_TAG:-}" ]]; then
    echo "release: commits since ${LAST_TAG}:"
    git log "${LAST_TAG}..HEAD" --oneline | sed 's/^/  /'
    echo "release: diffstat since ${LAST_TAG}:"
    git diff --shortstat "${LAST_TAG}" HEAD | sed 's/^/  /'
  else
    echo "release: no prior release tag — this tags the entire current history as ${VERSION}."
  fi
  echo ""
  if [[ "${RELEASE_YES:-}" == "1" ]]; then
    echo "release: RELEASE_YES=1 set — skipping confirmation prompt."
  elif [[ -t 0 ]]; then
    read -r -p "release: proceed with ${VERSION}? [y/N] " CONFIRM_ANS
    if [[ ! "${CONFIRM_ANS}" =~ ^[Yy]([Ee][Ss])?$ ]]; then
      echo "release: aborted — re-run when ready, or pass TAG= to force a specific version." >&2
      exit 1
    fi
  else
    echo "release: non-interactive shell and RELEASE_YES is not set — refusing to auto-confirm ${VERSION}. Set RELEASE_YES=1 or pass TAG= explicitly." >&2
    exit 1
  fi
fi

if [[ "${TAG_EXISTS_LOCALLY}" -eq 1 ]]; then
  TAG_SHA=$(git rev-parse "refs/tags/${VERSION}^{commit}")
  HEAD_SHA=$(git rev-parse HEAD)
  if [[ "${TAG_SHA}" != "${HEAD_SHA}" ]]; then
    echo "release: tag ${VERSION} already exists locally at ${TAG_SHA}, not HEAD (${HEAD_SHA})." >&2
    exit 1
  fi
  echo "release: tag ${VERSION} already exists at HEAD — resuming a prior attempt."
else
  git tag -a "${VERSION}" -m "Release ${VERSION}"
fi

UPSTREAM="origin/${BRANCH}"
if git rev-parse -q --verify "${UPSTREAM}" >/dev/null; then
  BRANCH_AHEAD=$(git rev-list --count "${UPSTREAM}..HEAD")
else
  BRANCH_AHEAD=1
fi

REMOTE_TAG_SHA=$(git ls-remote origin "refs/tags/${VERSION}" | awk '{print $1}')
if [[ -z "${REMOTE_TAG_SHA}" ]]; then
  TAG_PUSHED=0
else
  TAG_PUSHED=1
fi

if [[ "${BRANCH_AHEAD}" -gt 0 || "${TAG_PUSHED}" -eq 0 ]]; then
  HOOKS_PATH=$(git config --get core.hooksPath || true)
  if [[ "${HOOKS_PATH}" != "scripts/git-hooks" ]]; then
    echo "release: pre-push hook not wired — installing (git config core.hooksPath scripts/git-hooks)."
    git config core.hooksPath scripts/git-hooks
  fi
  echo "release: pushing ${BRANCH} + ${VERSION} — pre-push hook enforces the full gate."
  git push origin "${BRANCH}" "${VERSION}"
else
  echo "release: ${BRANCH} and ${VERSION} are already on origin — running the full gate inline (pre-push hook will not fire on a no-op push)."
  bash scripts/pre-push.sh
fi

echo "==> [3/5] cadence-aware heavy layer"
NOW=$(date +%s)
RUN_HEAVY=1
if [[ -f "${STAMP}" ]]; then
  LAST=$(cat "${STAMP}")
  AGE_DAYS=$(( (NOW - LAST) / 86400 ))
  if [[ "${AGE_DAYS}" -lt 7 ]]; then
    RUN_HEAVY=0
    echo "release: heavy layer last ran ${AGE_DAYS}d ago (<7d) — skipping (fast path)."
  fi
fi

if [[ "${RUN_HEAVY}" -eq 1 ]]; then
  echo "release: heavy layer stamp missing or stale (>=7d) — running weekly heavy verification."

  echo "  -> coverage threshold (>=${COVERAGE_THRESHOLD}%, per project blueprint in CLAUDE.md)"
  go test -coverprofile=coverage.out ./...
  COVERAGE=$(go tool cover -func=coverage.out | tail -1 | grep -oE '[0-9]+\.[0-9]+')
  if awk -v c="${COVERAGE}" -v t="${COVERAGE_THRESHOLD}" 'BEGIN{exit !(c<t)}'; then
    echo "release: coverage ${COVERAGE}% is below the ${COVERAGE_THRESHOLD}% threshold — release stopped before deploy." >&2
    exit 1
  fi
  echo "     coverage: ${COVERAGE}% (>= ${COVERAGE_THRESHOLD}%)"

  echo "  -> cross-platform artifact build (goreleaser --snapshot, all 5 os/arch targets)"
  if ! command -v goreleaser >/dev/null 2>&1; then
    echo "release: goreleaser not found on PATH. Run 'make tool-install'." >&2
    exit 1
  fi
  make release-snapshot

  date +%s > "${STAMP}"
  echo "release: heavy layer passed — stamp refreshed."
fi

echo "==> [4/5] deploy"
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "release: GITHUB_TOKEN is not set. Expected a token with 'contents:write' (+ 'packages:write' for Homebrew/Scoop pushes) scope." >&2
  echo "release: export GITHUB_TOKEN=<token> and re-run 'make release TAG=${VERSION}'." >&2
  exit 1
fi
if ! command -v goreleaser >/dev/null 2>&1; then
  echo "release: goreleaser not found on PATH. Run 'make tool-install'." >&2
  exit 1
fi
goreleaser release --clean

echo "==> [5/5] verify-live"
if ! command -v gh >/dev/null 2>&1; then
  echo "release: DEPLOYED BUT NOT VERIFIED — 'gh' CLI not found on PATH, cannot confirm the live release." >&2
  exit 1
fi

REMOTE_COMMIT_SHA=$(git ls-remote origin "refs/tags/${VERSION}^{}" | awk '{print $1}')
LOCAL_SHA=$(git rev-parse HEAD)
if [[ "${REMOTE_COMMIT_SHA}" != "${LOCAL_SHA}" ]]; then
  echo "release: DEPLOYED BUT NOT VERIFIED — remote tag ${VERSION} points at '${REMOTE_COMMIT_SHA:-<missing>}', local HEAD is ${LOCAL_SHA}." >&2
  exit 1
fi

if ! gh release view "${VERSION}" --repo "${REPO_SLUG}" >/dev/null 2>&1; then
  echo "release: DEPLOYED BUT NOT VERIFIED — GitHub release ${VERSION} not found via 'gh release view'." >&2
  exit 1
fi

ASSET_COUNT=$(gh release view "${VERSION}" --repo "${REPO_SLUG}" --json assets -q '.assets | length')
if ! [[ "${ASSET_COUNT}" =~ ^[0-9]+$ ]]; then
  echo "release: DEPLOYED BUT NOT VERIFIED — could not parse an asset count from 'gh release view' output: '${ASSET_COUNT}'." >&2
  exit 1
fi
if [[ "${ASSET_COUNT}" -lt 6 ]]; then
  echo "release: DEPLOYED BUT NOT VERIFIED — expected >=6 assets (5 platform archives + checksums.txt), found ${ASSET_COUNT}." >&2
  exit 1
fi

echo "release: verify-live OK — ${VERSION} is live at commit ${LOCAL_SHA:0:12}, ${ASSET_COUNT} assets published."
echo "release: https://github.com/${REPO_SLUG}/releases/tag/${VERSION}"

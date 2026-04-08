#!/bin/bash
set -e

SPEC_FILE=".claude/SPEC.md"
CLAUDE_FILE=".claude/CLAUDE.md"
DECISIONS_FILE=".claude/DECISIONS.md"
OFF_LIMITS=("agents/rbac-agent/rules" "agents/entra-agent/rules" "terraform")
MAX_ITERATIONS=5
ITERATION=0

echo "🚀 Starting autonomous run — $(date)"
echo "Branch: $(git branch --show-current)"
echo "Spec: $SPEC_FILE"

# Load .env if present and key not already in environment
if [[ -z "$ANTHROPIC_API_KEY" && -f ".env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Safety check — API key must be set so runs bill to API, not subscription
if [[ -z "$ANTHROPIC_API_KEY" ]]; then
  echo "❌ HALT: ANTHROPIC_API_KEY is not set"
  echo "   Set it in your host environment before opening the devcontainer."
  exit 1
fi

# Safety check — must be on feature branch
BRANCH=$(git branch --show-current)
if [[ "$BRANCH" == "main" || "$BRANCH" == "master" ]]; then
  echo "❌ HALT: Cannot run on main branch"
  exit 1
fi

while [ $ITERATION -lt $MAX_ITERATIONS ]; do
  ITERATION=$((ITERATION + 1))
  echo ""
  echo "--- Iteration $ITERATION of $MAX_ITERATIONS ---"

  # Run Claude Code non-interactively with API key auth
  # --dangerously-skip-permissions is appropriate here: the devcontainer
  # is the security boundary (read-only kubeconfig, scoped to kind cluster only)
  claude --print --dangerously-skip-permissions \
    "Read $CLAUDE_FILE and $DECISIONS_FILE for context.
     Your goal is in $SPEC_FILE.
     Execute the next uncompleted task.
     Log your decisions to $DECISIONS_FILE.
     When all success criteria are met, output DONE." \
    > .claude/last-output.txt 2>&1

  # Detect rate limit or auth errors and halt cleanly
  if grep -qi "rate limit\|usage limit\|quota\|unauthorized\|invalid api key" .claude/last-output.txt; then
    echo "❌ HALT: Claude API error detected — check last-output.txt"
    cat .claude/last-output.txt
    exit 1
  fi

  # Check for completion signal
  if grep -q "DONE" .claude/last-output.txt; then
    echo "✅ Agent signaled completion"
    break
  fi

  # Check for off-limits file modifications
  for path in "${OFF_LIMITS[@]}"; do
    if git diff --name-only | grep -q "$path"; then
      echo "❌ HALT: Agent modified off-limits path: $path"
      git checkout -- .
      exit 1
    fi
  done

  # Atomic commit if there are changes
  if ! git diff --quiet || ! git diff --cached --quiet; then
    git add -A
    # Pre-commit hooks (e.g. trailing-whitespace) may auto-fix files and exit 1.
    # Re-stage and retry once so those fixes land in the commit.
    if ! git commit -m "autonomous: iteration $ITERATION — $(date +%Y%m%d-%H%M%S)"; then
      git add -A
      git commit -m "autonomous: iteration $ITERATION — $(date +%Y%m%d-%H%M%S)"
    fi
    echo "✅ Committed iteration $ITERATION"
  fi

  sleep 2
done

echo ""
echo "🏁 Run complete — $(date)"
echo "Review: git log --oneline $(git branch --show-current)"
echo "Decisions: cat $DECISIONS_FILE"

# Open PR automatically on completion
if grep -q "DONE" .claude/last-output.txt; then
  echo "✅ Agent signaled completion — opening PR"
  gh pr create \
    --title "feat: CIS-5.1.4 subresource gap and admin/edit cluster binding check" \
    --body "$(cat .claude/DECISIONS.md)" \
    --base main \
    --head "$(git branch --show-current)" \
    --label "autonomous-run"
fi

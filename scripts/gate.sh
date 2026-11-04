#!/usr/bin/env bash
# Pre-push gate. Run from the repository root: bash scripts/gate.sh
# Prints PASS or FAIL for each step and ends with "GATE GREEN <sha>" or "GATE RED <sha>".
# Exit code is 0 only when every step passes.
#
# GATE_TEST_CMD overrides the test command (default: python -m pytest -q). It exists so the gate itself
# can be exercised in a scratch repository that has no test suite.
set -u
cd "$(git rev-parse --show-toplevel)" || { echo "not inside a git repository"; exit 2; }

RED=0
step() {  # step <name> <exit-code>: print the result and remember any failure
  if [ "$2" -eq 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; RED=1; fi
}

# The banned words are assembled from character codes so this file never contains them itself.
WORD_A=$(printf '\103\154\141\165\144\145')                    # first banned name
WORD_B=$(printf '\101\156\164\150\162\157\160\151\143')        # second banned name
BANNED="$WORD_A|$WORD_B"
HANDOFF="$(printf '\103\114\101\125\104\105').md"              # handoff notes file, must stay untracked

# 1. Full test suite. Show only the tail so a failure is readable.
TEST_CMD=${GATE_TEST_CMD:-"python -m pytest -q"}
OUT=$($TEST_CMD 2>&1); RC=$?
echo "$OUT" | tail -15
step "tests ($TEST_CMD)" $RC

# 2. Forbidden references: the banned names in any tracked text file or in the last 50 commit messages,
#    plus automated-trailer phrases in those commit messages.
BAD=0
REFS=$(git grep -I -i -l -E "$BANNED" -- . ':!vendor' 2>/dev/null)
[ -n "$REFS" ] && { BAD=1; echo "$REFS" | sed 's/^/  file: /'; }
if git log -50 --format=%B 2>/dev/null | grep -i -E -q "$BANNED|Co-Authored-By:|Generated with"; then
  BAD=1; echo "  a recent commit message has a forbidden reference"
fi
step "forbidden references" $BAD

# 3. Secrets in tracked files (vendor wheels and test fixtures are skipped): private key headers,
#    cloud access key ids, API-style tokens, and password assignments outside the docs.
BAD=0
SKIP=(':!vendor' ':!tests/fixtures')
git grep -I -n -E -e '-{5}BEGIN' -e 'AKIA[0-9A-Z]{16}' -e 'sk-[A-Za-z0-9]{20,}' -- . "${SKIP[@]}" && BAD=1
git grep -I -n -i -E "(password|passwd)[[:space:]]*[:=][[:space:]]*[\"'][^\"']{4,}[\"']" -- . "${SKIP[@]}" ':!docs' ':!*.md' && BAD=1
step "secret scan" $BAD

# 4. Whitespace errors in the latest commit (trailing spaces, stray conflict markers).
git show --check --format= HEAD >/dev/null 2>&1
step "git diff --check" $?

# 5. The handoff notes file must never be committed.
BAD=0
git ls-files | grep -i -E "(^|/)$HANDOFF\$" && BAD=1
step "handoff file untracked" $BAD

SHA=$(git rev-parse --short HEAD 2>/dev/null || echo none)
if [ $RED -eq 0 ]; then echo "GATE GREEN $SHA"; exit 0; fi
echo "GATE RED $SHA"; exit 1

# shellcheck shell=bash disable=SC2016,SC2034,SC2154
# Cases for scripts/check-workflow-pins.sh: the arithmetic of a job beside a
# secret. bash evaluates the value of every name in an arithmetic text as
# arithmetic in turn, and a subscript in a value runs the command it holds,
# so every operand is a number written out, one the shell sets, or a name
# every value of which is a number the script made and which an assignment
# sets on every way to the read. Sourced by
# scripts/check-workflow-pins-tests.sh.

HELD_FILES=()
OPERAND="an arithmetic operand that is not a number the script made"
held_case "an arithmetic expansion of a variable from the environment is refused" 1 "$HELD, line 7: $OPERAND (VALUE)" 'echo $((VALUE + 1))'
held_case "an arithmetic expansion of a parameter is refused" 1 "$HELD, line 7: $OPERAND (\$1)" 'f() { echo $(( $1 * 2 )); }' 'f 3'
held_case "a base prefix before a parameter is refused" 1 "$HELD, line 7: $OPERAND (\$1)" 'f() { local y=$((10#$1)); echo "$y"; }' 'f 08'
held_case "an arithmetic expansion of a substitution is refused" 1 "$HELD, line 7: $OPERAND (\$(substitution))" 'echo $(( $(cat count) + 1 ))'
held_case "an arithmetic command on a variable from the environment is refused" 1 "$HELD, line 7: $OPERAND (n)" '(( n++ ))'
held_case "a conditional comparison of a variable from the environment is refused" 1 "$HELD, line 7: $OPERAND (\$COUNT)" '[[ $COUNT -gt 0 ]] && echo some'
held_case "let on a variable from the environment is refused" 1 "$HELD, line 7: $OPERAND (i)" 'let i=i+1'
held_case "an array subscript from the environment is refused" 1 "$HELD, line 8: $OPERAND (\$INDEX)" 'names=(a b c)' 'echo "${names[$INDEX]}"'
held_case "an array element set at a subscript from the environment is refused" 1 "$HELD, line 7: $OPERAND (\$INDEX)" 'names[$INDEX]=x'
held_case "an array element unset at a subscript from the environment is refused" 1 "$HELD, line 7: $OPERAND (\$INDEX)" 'unset "names[$INDEX]"'
held_case "a substring at an offset from the environment is refused" 1 "$HELD, line 8: $OPERAND (\$OFFSET)" 's=abcdef' 'echo "${s:$OFFSET:2}"'
held_case "an integer variable is refused" 1 "$HELD, line 7: an integer variable (declare -i)" 'declare -i total' 'total=$VALUE'
held_case "a name the script sets after the read is refused" 1 "$HELD, line 7: $OPERAND (n)" 'echo $((n + 1))' 'n=1'
held_case "a name the script sets in a branch that may not run is refused" 1 "$HELD, line 8: $OPERAND (n)" 'if [ -n "$X" ]; then n=1; fi' 'echo $((n + 1))'
held_case "a name the script sets in the other branch is refused" 1 "$HELD, line 7: $OPERAND (n)" 'if [ -n "$X" ]; then n=1; else echo $((n + 1)); fi'
held_case "a name the script sets in a loop that may not run is refused" 1 "$HELD, line 8: $OPERAND (n)" 'while read -r line; do n=1; done < list' 'echo $((n + 1))'
held_case "a name the script sets in a subshell is refused" 1 "$HELD, line 8: $OPERAND (n)" '(n=1)' 'echo $((n + 1))'
held_case "a name the script sets after || is refused" 1 "$HELD, line 8: $OPERAND (n)" '[ -f x ] || n=1' 'echo $((n + 1))'
held_case "a name the script sets in a pipeline is refused" 1 "$HELD, line 8: $OPERAND (n)" 'n=1 | cat' 'echo $((n + 1))'
held_case "a name the script sets from the environment as well is refused" 1 "$HELD, line 9: $OPERAND (n)" 'n=0' 'n=$VALUE' 'echo $((n + 1))'
held_case "a name the script sets from a word, which arithmetic evaluates, is refused" 1 "$HELD, line 8: $OPERAND (n)" 'n=other' 'echo $((n + 1))'
held_case "a name the script sets from text a command prints is refused" 1 "$HELD, line 8: $OPERAND (n)" 'n=$(cat count)' 'echo $((n + 1))'
held_case "a name the script assigns from itself first is refused" 1 "$HELD, line 7: $OPERAND (n)" 'n=$((n + 1))'
held_case "the counter, the clock and the wait of a publish loop pass" 0 "OK: every action" \
  'attempt=0' \
  'while [ "$attempt" -lt 10 ]; do' \
  '  attempt=$((attempt + 1))' \
  '  if [ -n "$out" ]; then' \
  '    after=$(printf "%s" "$out" | sed -E "s/.*after //I")' \
  '    target=$(date -u -d "$after" +%s 2>/dev/null || echo 0)' \
  '    now=$(date -u +%s)' \
  '    if [ "$target" -gt "$now" ]; then wait=$((target - now + 10)); else wait=120; fi' \
  '    sleep "$wait"' \
  '  fi' \
  'done'
held_case "a count a command prints passes" 0 "OK: every action" 'lines=$(wc -l < notes)' 'found=$(grep -c x notes || true)' 'echo $((lines + found))'
held_case "a number expr reads from a parameter passes" 0 "OK: every action" 'valid() {' '  local y' '  y=$(expr "$1" + 0) || return 1' '  [ $((y % 4)) -eq 0 ]' '}' 'valid 2028'
held_case "a loop counter the arithmetic assigns first passes" 0 "OK: every action" 'n=4' 'for ((i = 0; i < n; i++)); do echo "$i"; done'
held_case "the status of a command passes" 0 "OK: every action" 'status=0' 'cargo publish --locked || status=$?' 'exit $((status))'
held_case "the numbers the shell sets pass" 0 "OK: every action" 'echo $(( $# + RANDOM % 6 + ${#name} ))' 'echo "${#names[@]}" "${names[@]}"'
held_case "a comparison inside [ ] evaluates nothing and passes" 0 "OK: every action" '[ "$COUNT" -gt 0 ] && echo some'
held_case "a name set in the same branch before the read passes" 0 "OK: every action" 'if [ -n "$X" ]; then n=1; echo $((n + 1)); fi'
free_case "arithmetic on a variable from the environment in a job that holds nothing passes" 'echo $((VALUE + 1))' '[[ $COUNT -gt 0 ]] && echo some'
held_case "a legacy arithmetic expansion is refused" 1 "$HELD, line 7: a legacy arithmetic expansion (\$[...]): write it as \$((...))" 'echo "$[COUNT + 1]"'
held_case "let after builtin on a variable from the environment is refused" 1 "$HELD, line 7: $OPERAND (i)" 'builtin let i=i+1'
held_case "a test of an array element at a subscript from the environment is refused" 1 "$HELD, line 7: $OPERAND (\$INDEX)" '[[ -v names[$INDEX] ]] && echo set'
held_case "a test builtin of an array element at a subscript from the environment is refused" 1 "$HELD, line 7: $OPERAND (\$INDEX)" 'test -v "names[$INDEX]" && echo set'
held_case "a read into an array element at a subscript from the environment is refused" 1 "$HELD, line 7: $OPERAND (\$INDEX)" 'read -r "names[$INDEX]" < list'
held_case "a legacy arithmetic text in single quotes is text and passes" 0 "OK: every action" "echo '\$[COUNT + 1]'"

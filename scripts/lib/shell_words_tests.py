"""Crafted cases for scripts/lib/shell_words.py, run by
scripts/check-workflow-pins-tests.sh.

Each script pins every command the lexer returns: its line, the operator
that joined it to the one before, each word's text, parts and line, each
redirection with its target, each here-document body with its offset, and
every problem with its line. Run with `python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shell_words as S


def line_index(text):
    starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]

    def line_of(offset):
        return sum(1 for s in starts if s <= offset)
    return line_of


def word(w):
    return (w.raw, tuple(w.parts), w.line)


def dump(script):
    commands = []
    for c in script.commands:
        redirects = tuple((op, word(t) if t else None) for op, t in c.redirects)
        commands.append((c.line, c.joined_by, tuple(word(w) for w in c.words), redirects, tuple(script.bodies_of(c))))
    return (tuple(commands), tuple(script.problems))


SCRIPTS = [
  ('a command then a subshell', 'a (b)',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '(', (('b', (('lit', 'b'),), 1),), (), ())), ())),
  ('array with an escaped closing parenthesis', 'a=(\\))b',
   (((1, '\n', (('a=(\\))b', (('lit', 'a'), ('lit', '='), ('exp', 'a=(\\))'), ('lit', 'b')), 1),), (), ()),), ())),
  ('array with a quote before the close', "a=('x')b",
   (((1, '\n', (("a=('x')b", (('lit', 'a'), ('lit', '='), ('exp', "a=('x')"), ('lit', 'b')), 1),), (), ()),), ())),
  ('parameter expansion with quotes then text', "echo ${a:-'x'}b",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("${a:-'x'}b", (('exp', "${a:-'x'}"), ('lit', 'b')), 1)), (), ()),), ())),
  ('parameter expansion with an escape then text', 'echo ${a:-\\}}b',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('${a:-\\}}b', (('exp', '${a:-\\}}'), ('lit', 'b')), 1)), (), ()),), ())),
  ('nested parameter expansion then text', 'echo ${a:-${}x}',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('${a:-${}x}', (('exp', '${a:-${}x}'),), 1)), (), ()),), ())),
  ('function definition', 'f() { g; }',
   (((1, '\n', (('f', (('lit', 'f'),), 1),), (), ()), (1, ')', (('{', (('lit', '{'),), 1), ('g', (('lit', 'g'),), 1)), (), ()), (1, ';', (('}', (('lit', '}'),), 1),), (), ())), ())),
  ('arithmetic substitution without spaces', '(($(a)))',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()),), ())),
  ('escaped backslash before a substitution in a here-document', 'cat <<EOF\n\\\\$(a)\nEOF',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('\\\\$(a)\n', 10),)), (2, '\n', (('a', (('lit', 'a'),), 2),), (), ())), ())),
  ('two substitutions in a here-document', 'cat <<EOF\n$(a)$(b)\nEOF',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('$(a)$(b)\n', 10),)), (2, '\n', (('a', (('lit', 'a'),), 2),), (), ()), (2, '\n', (('b', (('lit', 'b'),), 2),), (), ())), ())),
  ('adjacent backticks in a here-document', 'cat <<EOF\n`a``b`\nEOF',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('`a``b`\n', 10),)), (2, '\n', (('a', (('lit', 'a'),), 2),), (), ()), (2, '\n', (('b', (('lit', 'b'),), 2),), (), ())), ())),
  ('backticks with two letters', 'echo `ab`',
   (((1, '\n', (('ab', (('lit', 'a'), ('lit', 'b')), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('`ab`', (('exp', '`ab`'),), 1)), (), ())), ())),
  ('empty backticks', 'echo `` x',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('``', (('exp', '``'),), 1), ('x', (('lit', 'x'),), 1)), (), ()),), ())),
  ('array with a parenthesis in quotes', "a=('x)') b",
   (((1, '\n', (("a=('x)')", (('lit', 'a'), ('lit', '='), ('exp', "a=('x)')")), 1), ('b', (('lit', 'b'),), 1)), (), ()),), ())),
  ('array followed by text', 'a=(x)y',
   (((1, '\n', (('a=(x)y', (('lit', 'a'), ('lit', '='), ('exp', 'a=(x)'), ('lit', 'y')), 1),), (), ()),), ())),
  ('process substitution followed by text', 'diff <(a)x',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('diff', (('lit', 'd'), ('lit', 'i'), ('lit', 'f'), ('lit', 'f')), 1), ('<(a)x', (('exp', '<(a)'), ('lit', 'x')), 1)), (), ())), ())),
  ('empty single quotes', "echo '' x",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("''", (), 1), ('x', (('lit', 'x'),), 1)), (), ()),), ())),
  ('array with an escaped parenthesis', 'a=(x\\) y) z',
   (((1, '\n', (('a=(x\\) y)', (('lit', 'a'), ('lit', '='), ('exp', 'a=(x\\) y)')), 1), ('z', (('lit', 'z'),), 1)), (), ()),), ())),
  ('array with empty quotes', "a=('' x) y",
   (((1, '\n', (("a=('' x)", (('lit', 'a'), ('lit', '='), ('exp', "a=('' x)")), 1), ('y', (('lit', 'y'),), 1)), (), ()),), ())),
  ('array comment with a parenthesis', 'a=(x #c)\n y) z',
   (((1, '\n', (('a=(x #c)\n y)', (('lit', 'a'), ('lit', '='), ('exp', 'a=(x #c)\n y)')), 1), ('z', (('lit', 'z'),), 2)), (), ()),), ())),
  ('backticks in double quotes with two letters', 'echo "`ab`"',
   (((1, '\n', (('ab', (('lit', 'a'), ('lit', 'b')), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('"`ab`"', (('exp', '`ab`'),), 1)), (), ())), ())),
  ('expression then text', 'echo ${{a}}b',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('${{a}}b', (('exp', '${{a}}'), ('lit', 'b')), 1)), (), ()),), ())),
  ('arithmetic substitution', 'echo $(($(a)))',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$(($(a)))', (('exp', '$(($(a)))'),), 1)), (), ())), ())),
  ('empty parameter expansion', 'echo ${}x',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('${}x', (('exp', '${}'), ('lit', 'x')), 1)), (), ()),), ())),
  ('parameter expansion with empty quotes', "echo ${a:-''}x",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("${a:-''}x", (('exp', "${a:-''}"), ('lit', 'x')), 1)), (), ()),), ())),
  ('ansi-c then text', "echo $'a'b",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("$'a'b", (('lit', 'a'), ('lit', 'b')), 1)), (), ()),), ())),
  ('pattern parenthesis then text', 'case x in a)b;; esac',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('x', (('lit', 'x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (1, ')', (('b', (('lit', 'b'),), 1),), (), ())), ())),
  ('words and spaces', 'a  b\tc',
   (((1, '\n', (('a', (('lit', 'a'),), 1), ('b', (('lit', 'b'),), 1), ('c', (('lit', 'c'),), 1)), (), ()),), ())),
  ('single quotes', "echo 'a b' x'y'z",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("'a b'", (('lit', 'a b'),), 1), ("x'y'z", (('lit', 'x'), ('lit', 'y'), ('lit', 'z')), 1)), (), ()),), ())),
  ('double quotes with escapes', 'echo "a \\$ \\` \\" \\\\ \\n b"',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('"a \\$ \\` \\" \\\\ \\n b"', (('lit', 'a'), ('lit', ' '), ('lit', '$'), ('lit', ' '), ('lit', '`'), ('lit', ' '), ('lit', '"'), ('lit', ' '), ('lit', '\\'), ('lit', ' '), ('lit', '\\'), ('lit', 'n'), ('lit', ' '), ('lit', 'b')), 1)), (), ()),), ())),
  ('double quote continued line', 'echo "a\\\nb"',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('"a\\\nb"', (('lit', 'a'), ('lit', 'b')), 1)), (), ()),), ())),
  ('backslash escapes', 'echo a\\ b \\$x \\\\',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('a\\ b', (('lit', 'a'), ('lit', ' '), ('lit', 'b')), 1), ('\\$x', (('lit', '$'), ('lit', 'x')), 1), ('\\\\', (('lit', '\\'),), 1)), (), ()),), ())),
  ('line continuation between words', 'echo a \\\n  b',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('a', (('lit', 'a'),), 1), ('b', (('lit', 'b'),), 2)), (), ()),), ())),
  ('line continuation inside a word', 'ec\\\nho x',
   (((1, '\n', (('ec\\\nho', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('x', (('lit', 'x'),), 2)), (), ()),), ())),
  ('comment', 'a # b c\nd',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (2, '\n', (('d', (('lit', 'd'),), 2),), (), ())), ())),
  ('hash inside a word', 'echo a#b',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('a#b', (('lit', 'a'), ('lit', '#'), ('lit', 'b')), 1)), (), ()),), ())),
  ('operators', 'a && b || c ; d & e | f |& g ;; h',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '&&', (('b', (('lit', 'b'),), 1),), (), ()), (1, '||', (('c', (('lit', 'c'),), 1),), (), ()), (1, ';', (('d', (('lit', 'd'),), 1),), (), ()), (1, '&', (('e', (('lit', 'e'),), 1),), (), ()), (1, '|', (('f', (('lit', 'f'),), 1),), (), ()), (1, '|&', (('g', (('lit', 'g'),), 1),), (), ()), (1, ';;', (('h', (('lit', 'h'),), 1),), (), ())), ())),
  ('case operators', 'case x in a) b ;& c) d ;;& esac',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('x', (('lit', 'x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (1, ')', (('b', (('lit', 'b'),), 1),), (), ()), (1, ')', (('d', (('lit', 'd'),), 1),), (), ())), ())),
  ('newlines', 'a\nb\n\nc',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (2, '\n', (('b', (('lit', 'b'),), 2),), (), ()), (4, '\n', (('c', (('lit', 'c'),), 4),), (), ())), ())),
  ('output redirections', 'a >f >>g >|h 2>i &>j &>>k >&2 2>&1 1>&- 10>l {fd}>m',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (('>', ('f', (('lit', 'f'),), 1)), ('>>', ('g', (('lit', 'g'),), 1)), ('>|', ('h', (('lit', 'h'),), 1)), ('>', ('i', (('lit', 'i'),), 1)), ('&>', ('j', (('lit', 'j'),), 1)), ('&>>', ('k', (('lit', 'k'),), 1)), ('>&', ('2', (('lit', '2'),), 1)), ('>&', ('1', (('lit', '1'),), 1)), ('>&', ('-', (('lit', '-'),), 1)), ('>', ('l', (('lit', 'l'),), 1)), ('>', ('m', (('lit', 'm'),), 1))), ()),), ())),
  ('input redirections', 'a <f <>g 2<&1 <<<w',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (('<', ('f', (('lit', 'f'),), 1)), ('<>', ('g', (('lit', 'g'),), 1)), ('<&', ('1', (('lit', '1'),), 1)), ('<<<', ('w', (('lit', 'w'),), 1))), ()),), ())),
  ('redirection before the command', '<in a b',
   (((1, '\n', (('a', (('lit', 'a'),), 1), ('b', (('lit', 'b'),), 1)), (('<', ('in', (('lit', 'i'), ('lit', 'n')), 1)),), ()),), ())),
  ('redirection to a process substitution', 'a < <(b c) > >(d)',
   (((1, '\n', (('b', (('lit', 'b'),), 1), ('c', (('lit', 'c'),), 1)), (), ()), (1, '\n', (('d', (('lit', 'd'),), 1),), (), ()), (1, '\n', (('a', (('lit', 'a'),), 1),), (('<', ('<(b c)', (('exp', '<(b c)'),), 1)), ('>', ('>(d)', (('exp', '>(d)'),), 1))), ())), ())),
  ('process substitution as a word', 'diff <(a) >(b)',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('b', (('lit', 'b'),), 1),), (), ()), (1, '\n', (('diff', (('lit', 'd'), ('lit', 'i'), ('lit', 'f'), ('lit', 'f')), 1), ('<(a)', (('exp', '<(a)'),), 1), ('>(b)', (('exp', '>(b)'),), 1)), (), ())), ())),
  ('here-document', 'cat <<EOF\nline $(inner)\nEOF\nnext',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('line $(inner)\n', 10),)), (2, '\n', (('inner', (('lit', 'i'), ('lit', 'n'), ('lit', 'n'), ('lit', 'e'), ('lit', 'r')), 2),), (), ()), (4, '\n', (('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 4),), (), ())), ())),
  ('quoted here-document', "cat <<'EOF'\n$(not)\nEOF\nnext",
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ("'EOF'", (('lit', 'EOF'),), 1)),), (('$(not)\n', 12),)), (4, '\n', (('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 4),), (), ())), ())),
  ('escaped here-document delimiter', 'cat <<\\EOF\n$(not)\nEOF',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('\\EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('$(not)\n', 11),)),), ())),
  ('tab-stripped here-document', 'cat <<-EOF\n\tbody\n\tEOF\nnext',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<-', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('\tbody\n', 11),)), (4, '\n', (('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 4),), (), ())), ())),
  ('two here-documents', 'cat <<A <<B\na\nA\nb\nB\nnext',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('A', (('lit', 'A'),), 1)), ('<<', ('B', (('lit', 'B'),), 1))), (('a\n', 12), ('b\n', 16))), (6, '\n', (('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 6),), (), ())), ())),
  ('here-document with backticks', 'cat <<EOF\n`inner one`\n\\`not\nEOF',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('`inner one`\n\\`not\n', 10),)), (2, '\n', (('inner', (('lit', 'i'), ('lit', 'n'), ('lit', 'n'), ('lit', 'e'), ('lit', 'r')), 2), ('one', (('lit', 'o'), ('lit', 'n'), ('lit', 'e')), 2)), (), ())), ())),
  ('here-document in a substitution', 'x=$(cat <<EOF\nbody\nEOF\n)\nnext',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), (('body\n', 14),)), (1, '\n', (('x=$(cat <<EOF\nbody\nEOF\n)', (('lit', 'x'), ('lit', '='), ('exp', '$(cat <<EOF\nbody\nEOF\n)')), 1),), (), ()), (5, '\n', (('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 5),), (), ())), ())),
  ('command substitution', 'echo $(a b) c',
   (((1, '\n', (('a', (('lit', 'a'),), 1), ('b', (('lit', 'b'),), 1)), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$(a b)', (('exp', '$(a b)'),), 1), ('c', (('lit', 'c'),), 1)), (), ())), ())),
  ('nested substitution', 'echo $(a $(b c) d)',
   (((1, '\n', (('b', (('lit', 'b'),), 1), ('c', (('lit', 'c'),), 1)), (), ()), (1, '\n', (('a', (('lit', 'a'),), 1), ('$(b c)', (('exp', '$(b c)'),), 1), ('d', (('lit', 'd'),), 1)), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$(a $(b c) d)', (('exp', '$(a $(b c) d)'),), 1)), (), ())), ())),
  ('substitution in double quotes', 'echo "x $(a) y"',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('"x $(a) y"', (('lit', 'x'), ('lit', ' '), ('exp', '$(a)'), ('lit', ' '), ('lit', 'y')), 1)), (), ())), ())),
  ('backticks', 'echo `a b` c',
   (((1, '\n', (('a', (('lit', 'a'),), 1), ('b', (('lit', 'b'),), 1)), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('`a b`', (('exp', '`a b`'),), 1), ('c', (('lit', 'c'),), 1)), (), ())), ())),
  ('escaped backticks in backticks', 'echo `echo \\`b\\``',
   (((1, '\n', (('b', (('lit', 'b'),), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('`b`', (('exp', '`b`'),), 1)), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('`echo \\`b\\``', (('exp', '`echo \\`b\\``'),), 1)), (), ())), ())),
  ('substitution in arithmetic', 'echo $(( $(a) + `b` )) x; (( $(c) ))',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('b', (('lit', 'b'),), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$(( $(a) + `b` ))', (('exp', '$(( $(a) + `b` ))'),), 1), ('x', (('lit', 'x'),), 1)), (), ()), (1, '\n', (('c', (('lit', 'c'),), 1),), (), ())), ())),
  ('backtick in double quotes', 'echo "x `a` y"',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('"x `a` y"', (('lit', 'x'), ('lit', ' '), ('exp', '`a`'), ('lit', ' '), ('lit', 'y')), 1)), (), ())), ())),
  ('arithmetic', 'echo $((1 + (2 * 3))) x',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$((1 + (2 * 3)))', (('exp', '$((1 + (2 * 3)))'),), 1), ('x', (('lit', 'x'),), 1)), (), ()),), ())),
  ('arithmetic command', '(( i += 1 )); next',
   (((1, ';', (('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 1),), (), ()),), ())),
  ('parameter expansion', 'echo ${a:-"b c"} ${d:-$(e f)} ${g:-\'h\'} ${i:-${j}} ${k#\\}}',
   (((1, '\n', (('e', (('lit', 'e'),), 1), ('f', (('lit', 'f'),), 1)), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('${a:-"b c"}', (('exp', '${a:-"b c"}'),), 1), ('${d:-$(e f)}', (('exp', '${d:-$(e f)}'),), 1), ("${g:-'h'}", (('exp', "${g:-'h'}"),), 1), ('${i:-${j}}', (('exp', '${i:-${j}}'),), 1), ('${k#\\}}', (('exp', '${k#\\}}'),), 1)), (), ())), ())),
  ('expression', 'echo ${{ matrix.target }} x',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('${{ matrix.target }}', (('exp', '${{ matrix.target }}'),), 1), ('x', (('lit', 'x'),), 1)), (), ()),), ())),
  ('ansi-c quotes', "echo $'a\\tb\\x41\\101\\u00e9\\'\\q'",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("$'a\\tb\\x41\\101\\u00e9\\'\\q'", (('lit', "a\tbAAé'\\q"),), 1)), (), ()),), ())),
  ('locale quotes', 'echo $"a b"',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$"a b"', (('lit', 'a'), ('lit', ' '), ('lit', 'b')), 1)), (), ()),), ())),
  ('variables', 'echo $a $1 $@ $* $# $? $$ $! $- $ x',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$a', (('exp', '$a'),), 1), ('$1', (('exp', '$1'),), 1), ('$@', (('exp', '$@'),), 1), ('$*', (('exp', '$*'),), 1), ('$#', (('exp', '$#'),), 1), ('$?', (('exp', '$?'),), 1), ('$$', (('exp', '$$'),), 1), ('$!', (('exp', '$!'),), 1), ('$-', (('exp', '$-'),), 1), ('$', (('lit', '$'),), 1), ('x', (('lit', 'x'),), 1)), (), ()),), ())),
  ('dollar in double quotes', 'echo "$a $"',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('"$a $"', (('exp', '$a'), ('lit', ' '), ('lit', '$')), 1)), (), ()),), ())),
  ('array assignment', 'a=(x \'y z\' "w" $(v) # c\n u) next',
   (((1, '\n', (('v', (('lit', 'v'),), 1),), (), ()), (1, '\n', (('a=(x \'y z\' "w" $(v) # c\n u)', (('lit', 'a'), ('lit', '='), ('exp', 'a=(x \'y z\' "w" $(v) # c\n u)')), 1), ('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 2)), (), ())), ())),
  ('indexed array assignment', 'a[1]+=(x) next',
   (((1, '\n', (('a[1]+=(x)', (('lit', 'a'), ('lit', '['), ('lit', '1'), ('lit', ']'), ('lit', '+'), ('lit', '='), ('exp', 'a[1]+=(x)')), 1), ('next', (('lit', 'n'), ('lit', 'e'), ('lit', 'x'), ('lit', 't')), 1)), (), ()),), ())),
  ('subshell and group', '(a; (b)) { c; }',
   (((1, '(', (('a', (('lit', 'a'),), 1),), (), ()), (1, '(', (('b', (('lit', 'b'),), 1),), (), ()), (1, ')', (('{', (('lit', '{'),), 1), ('c', (('lit', 'c'),), 1)), (), ()), (1, ';', (('}', (('lit', '}'),), 1),), (), ())), ())),
  ('case statement', 'case $x in\n  a|b) c ;;\n  (d) e ;;\n  *) f\nesac\ng',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('$x', (('exp', '$x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (2, ')', (('c', (('lit', 'c'),), 2),), (), ()), (3, ')', (('e', (('lit', 'e'),), 3),), (), ()), (4, ')', (('f', (('lit', 'f'),), 4),), (), ()), (5, '\n', (('esac', (('lit', 'e'), ('lit', 's'), ('lit', 'a'), ('lit', 'c')), 5),), (), ()), (6, '\n', (('g', (('lit', 'g'),), 6),), (), ())), ())),
  ('case in a substitution', 'y=$(case $x in a) b ;; esac) z',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('$x', (('exp', '$x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (1, ')', (('b', (('lit', 'b'),), 1),), (), ()), (1, '\n', (('y=$(case $x in a) b ;; esac)', (('lit', 'y'), ('lit', '='), ('exp', '$(case $x in a) b ;; esac)')), 1), ('z', (('lit', 'z'),), 1)), (), ())), ())),
  ('case on one line', 'case x in a) b;; esac; c',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('x', (('lit', 'x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (1, ')', (('b', (('lit', 'b'),), 1),), (), ()), (1, ';', (('c', (('lit', 'c'),), 1),), (), ())), ())),
  ('words around a substitution', 'a$(b)c',
   (((1, '\n', (('b', (('lit', 'b'),), 1),), (), ()), (1, '\n', (('a$(b)c', (('lit', 'a'), ('exp', '$(b)'), ('lit', 'c')), 1),), (), ())), ())),
  ('empty', '',
   ((), ())),
  ('only a comment', '# x',
   ((), ())),
]
PROBLEMS = [
  ('quote not closed in an array', "a=('x",
   (((1, '\n', (("a=('x", (('lit', 'a'), ('lit', '='), ('exp', "a=('x")), 1),), (), ()),), ((1, 'an array that does not close'),))),
  ('quote not closed in a parameter expansion', "echo ${a:-'x",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("${a:-'x", (('exp', "${a:-'x"),), 1)), (), ()),), ((1, 'a parameter expansion that does not close'),))),
  ('substitution not closed before a final newline', 'echo $(a\n',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$(a\n', (('exp', '$(a\n'),), 1)), (), ())), ((1, 'a substitution that does not close'),))),
  ('esac as a command, then a stray pattern', 'case x in a) b\nesac\nx ;; y) z',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('x', (('lit', 'x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (1, ')', (('b', (('lit', 'b'),), 1),), (), ()), (2, '\n', (('esac', (('lit', 'e'), ('lit', 's'), ('lit', 'a'), ('lit', 'c')), 2),), (), ()), (3, '\n', (('x', (('lit', 'x'),), 3),), (), ()), (3, ';;', (('y', (('lit', 'y'),), 3),), (), ()), (3, ';;', (('z', (('lit', 'z'),), 3),), (), ())), ((3, 'a closing parenthesis that closes nothing'),))),
  ('stray parenthesis before a line break', 'a )\nb',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (2, '\n', (('b', (('lit', 'b'),), 2),), (), ())), ((1, 'a closing parenthesis that closes nothing'),))),
  ('stray parenthesis after a case with a leading pattern parenthesis', 'case x in (a) b;; esac\n)',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('x', (('lit', 'x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (1, ')', (('b', (('lit', 'b'),), 1),), (), ())), ((2, 'a closing parenthesis that closes nothing'),))),
  ('array with a comment at the end', 'a=(x #c',
   (((1, '\n', (('a=(x #c', (('lit', 'a'), ('lit', '='), ('exp', 'a=(x #c')), 1),), (), ()),), ((1, 'an array that does not close'),))),
  ('ansi-c escape at the end', "echo $'\\n",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("$'\\n", (('lit', '\n'),), 1)), (), ()),), ((1, 'a quote that does not close'),))),
  ('substitution not closed over lines', 'echo $(a\nb',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (2, '\n', (('b', (('lit', 'b'),), 2),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$(a\nb', (('exp', '$(a\nb'),), 1)), (), ())), ((2, 'a substitution that does not close'),))),
  ('stray ;; then a parenthesis', 'a ;; b ) c',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, ';;', (('b', (('lit', 'b'),), 1),), (), ()), (1, ';;', (('c', (('lit', 'c'),), 1),), (), ())), ((1, 'a closing parenthesis that closes nothing'),))),
  ('stray ;; after esac', 'case x in a) b;; esac; x ;; y) z',
   (((1, '\n', (('case', (('lit', 'c'), ('lit', 'a'), ('lit', 's'), ('lit', 'e')), 1), ('x', (('lit', 'x'),), 1), ('in', (('lit', 'i'), ('lit', 'n')), 1)), (), ()), (1, ')', (('b', (('lit', 'b'),), 1),), (), ()), (1, ';', (('x', (('lit', 'x'),), 1),), (), ()), (1, ';;', (('y', (('lit', 'y'),), 1),), (), ()), (1, ';;', (('z', (('lit', 'z'),), 1),), (), ())), ((1, 'a closing parenthesis that closes nothing'),))),
  ('stray parenthesis after a subshell', '(a) )',
   (((1, '(', (('a', (('lit', 'a'),), 1),), (), ()),), ((1, 'a closing parenthesis that closes nothing'),))),
  ('stray parenthesis on line 2', 'a\n) b',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (2, '\n', (('b', (('lit', 'b'),), 2),), (), ())), ((2, 'a closing parenthesis that closes nothing'),))),
  ('unclosed quote inside backticks', "echo `echo 'a`",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("'a", (('lit', 'a'),), 1)), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("`echo 'a`", (('exp', "`echo 'a`"),), 1)), (), ())), ((1, 'a quote that does not close'),))),
  ('ansi-c backslash at the end', "echo $'a\\",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("$'a\\", (('lit', 'a\\'),), 1)), (), ()),), ((1, 'a quote that does not close'),))),
  ('quote not closed', "echo 'a",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("'a", (('lit', 'a'),), 1)), (), ()),), ((1, 'a quote that does not close'),))),
  ('double quote not closed', 'echo "a',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('"a', (('lit', 'a'),), 1)), (), ()),), ((1, 'a quote that does not close'),))),
  ('backtick not closed', 'echo `a',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('`a', (('exp', '`a'),), 1)), (), ()),), ((1, 'a backtick substitution that does not close'),))),
  ('substitution not closed', 'echo $(a',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$(a', (('exp', '$(a'),), 1)), (), ())), ((1, 'a substitution that does not close'),))),
  ('parameter expansion not closed', 'echo ${a',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('${a', (('exp', '${a'),), 1)), (), ()),), ((1, 'a parameter expansion that does not close'),))),
  ('arithmetic not closed', 'echo $((1',
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ('$((1', (('exp', '$((1'),), 1)), (), ()),), ((1, 'an arithmetic expression that does not close'),))),
  ('array not closed', 'a=(x',
   (((1, '\n', (('a=(x', (('lit', 'a'), ('lit', '='), ('exp', 'a=(x')), 1),), (), ()),), ((1, 'an array that does not close'),))),
  ('here-document not closed', 'cat <<EOF\nx',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('EOF', (('lit', 'E'), ('lit', 'O'), ('lit', 'F')), 1)),), ()),), ((2, 'a here-document with no closing EOF'),))),
  ('here-document delimiter from an expansion', 'cat <<$X\nx\n$X',
   (((1, '\n', (('cat', (('lit', 'c'), ('lit', 'a'), ('lit', 't')), 1),), (('<<', ('$X', (('exp', '$X'),), 1)),), ()), (2, '\n', (('x', (('lit', 'x'),), 2),), (), ()), (3, '\n', (('$X', (('exp', '$X'),), 3),), (), ())), ((1, 'a here-document delimiter from an expansion'),))),
  ('redirection with no target', 'a >',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (('>', None),), ()),), ((1, 'a redirection with no target'),))),
  ('redirection before an operator', 'a > ; b',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (('>', None),), ()), (1, ';', (('b', (('lit', 'b'),), 1),), (), ())), ((1, 'a redirection with no target'),))),
  ('closing parenthesis that closes nothing', 'a ) b',
   (((1, '\n', (('a', (('lit', 'a'),), 1),), (), ()), (1, '\n', (('b', (('lit', 'b'),), 1),), (), ())), ((1, 'a closing parenthesis that closes nothing'),))),
  ('ansi-c not closed', "echo $'a",
   (((1, '\n', (('echo', (('lit', 'e'), ('lit', 'c'), ('lit', 'h'), ('lit', 'o')), 1), ("$'a", (('lit', 'a'),), 1)), (), ()),), ((1, 'a quote that does not close'),))),
]


def main():
    failures = []
    for name, text, want in SCRIPTS + PROBLEMS:
        got = dump(S.lex(text, line_index(text)))
        if got != want:
            failures.append("%s: lexed %r, wanted %r" % (name, got, want))
    w = S.lex('a"$b"c$(d)e', line_index('a"$b"c$(d)e')).commands[-1].words[0]
    for what, got, want in (("literal", w.literal(), None), ("head", w.head(), "a"), ("tail", w.tail(), "e")):
        if got != want:
            failures.append("word %s: %r, wanted %r" % (what, got, want))
    plain = S.lex("x'y'", line_index("x'y'")).commands[0].words[0]
    if (plain.literal(), plain.head(), plain.tail()) != ("xy", "xy", "xy"):
        failures.append("a literal word: %r" % ((plain.literal(), plain.head(), plain.tail()),))
    for text, want in (("case", "case"), ('"case"', None), ("'case'", None), ("\\case", None), ("ca'se'", None), ("$x", None)):
        got = S.lex(text, line_index(text)).commands[0].words[0].bare()
        if got != want:
            failures.append("bare word %r: %r, wanted %r" % (text, got, want))
    splitting = (("$c", True), ('"$c"', False), ("${c}", True), ('"${c:-x}"', False), ("$(x)", True), ('"$(x)"', False),
                 ("`x`", True), ('"`x`"', False), ("$((1))", True), ('"$((1))"', False), ('"$@"', True), ("$@", True),
                 ('"$*"', False), ('"${@:2}"', True), ('"${a[@]}"', True), ('"${!a[@]}"', True), ('"${#a[@]}"', False),
                 ('"${a[*]}"', False), ('"${{ x }}"', True), ("<(x)", False), ("a=(x y)", False), ("$'x y'", False), ("x", False),
                 ("{a,b}", True), ("x{a,b}y", True), ("{1..3}", True), ("{a..z}", True), ("{-1..9..2}", True),
                 ("{a,{b}}", True), ("{{a,b}}", True), ("{a{b,c}}", True), ('"{a,b}"', False), ("'{a,b}'", False),
                 ("\\{a,b}", False), ("{a\\,b}", False), ('{a",b}', False), ("{a}", False), ("{}", False), ("{a,", False),
                 ("a,b}", False), ("{a..}", False), ("{a..b..c}", False), ("HEAD@{1}", False), ("a*", True), ("a?", True),
                 ("[ab]", True), ("x[a]", True), ('"a*"', False), ("a\\*", False), ("'a?'", False), ("[", False),
                 ("[]", False), ("[[", False), ("]]", False), ("x={a,b}", False), ("a[1]=*", False), ("x+=a*", False))
    for text, want in splitting:
        got = S.lex(text, line_index(text)).commands[-1].words[0].splits
        if got != want:
            failures.append("word %r splits: %r, wanted %r" % (text, got, want))
    conditionals = (
        ("[[ $x =~ ^a(b|c)?$ ]] && d", [["[[", "$x", "=~", "^a", "b", "c", "?$", "]]"], ["d"]], []),
        ("if ! [[ a < b || -f x* ]]; then e; fi", [["if", "!", "[[", "a", "b", "-f", "x*", "]]"], ["then", "e"], ["fi"]], []),
        ("{ [[ (a) ]] | f; }", [["{", "[[", "a", "]]"], ["f"], ["}"]], []),
        ("while time [[ a&b ]]; do g; done", [["while", "time", "[[", "a", "b", "]]"], ["do", "g"], ["done"]], []),
        ("x [[ (y) ]]", [["x", "[["], ["y"], ["]]"]], []),
        ('"[[" a; b (c)', [['"[["', "a"], ["b"], ["c"]], []),
        ("[[ a ; b", [["[[", "a"], ["b"]], [(1, "a conditional expression that does not close")]),
        ("[[ a ]] ]]; c", [["[[", "a", "]]", "]]"], ["c"]], []),
        ("[[ a ;b", [["[[", "a"], ["b"]], [(1, "a conditional expression that does not close")]),
        ("[[ ]] && b (c)", [["[[", "]]"], ["b"], ["c"]], []),
        ("cat <<EOF\n\\a\\$(x)\nEOF", [["cat"]], []))
    for lead in ("if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"):
        text = lead + " [[ (a) ]]"
        got = [[w.raw for w in c.words] for c in S.lex(text, line_index(text)).commands]
        if got != [[lead, "[[", "a", "]]"]]:
            failures.append("conditional after %s: %r" % (lead, got))
    for text, want, problems in conditionals:
        lexed = S.lex(text, line_index(text))
        got = [[w.raw for w in c.words] for c in lexed.commands]
        if got != want or lexed.problems != problems:
            failures.append("conditional %r: %r %r, wanted %r %r" % (text, got, lexed.problems, want, problems))
    if any(w.splits for w in S.lex("[[ a* == {b,c} ]]", line_index("x")).commands[0].words):
        failures.append("a word of a conditional expression splits")
    for text, want in (("a{b,c}", True), ("a", False), ("{a}", False)):
        if S.expands(text) is not want:
            failures.append("expands %r: %r" % (text, S.expands(text)))
    text = "f() { a; }\ng () ( b )\nfunction h { c; }\nk (l)\nm=(n)\no x ( p )\nfunction q\n{ r; }"
    got = S.lex(text, line_index(text)).functions
    if got != {"f", "g", "h", "q"}:
        failures.append("functions of %r: %r" % (text, got))
    # The subshells and substitutions each command stands in: a command of
    # a substitution comes before the command that holds it.
    scopes = (
        ("cd /x; y=$(./a.sh)", [("cd", ()), ("./a.sh", (1,)), ("y=$(./a.sh)", ())]),
        ("(cd /x; b); ./a.sh", [("cd", (1,)), ("b", (1,)), ("./a.sh", ())]),
        ('X="$(cd "$(dirname "$0")" && pwd)"', [("dirname", (1, 2)), ("cd", (1,)), ("pwd", (1,)), ('X="$(cd "$(dirname "$0")" && pwd)"', ())]),
        ("a `cd x; b` c", [("cd", (1,)), ("b", (1,)), ("a", ())]),
        ("a <(b) | (c; (d)); e", [("b", (1,)), ("a", ()), ("c", (2,)), ("d", (2, 3)), ("e", ())]),
        ("f() ( cd x ); g", [("f", ()), ("cd", (2,)), ("g", ())]),
        ('echo "${x:-$(c)}" $((1 + $(d)))', [("c", (1,)), ("d", (2,)), ("echo", ())]),
        ("{ cd x; }; a", [("{", ()), ("}", ()), ("a", ())]),
        ("cat <<EOF\n$(cd x)\nEOF\nb", [("cat", ()), ("cd", (1,)), ("b", ())]))
    for text, want in scopes:
        got = [(c.words[0].raw, c.scope) for c in S.lex(text, line_index(text)).commands]
        if got != want:
            failures.append("scopes of %r: %r, wanted %r" % (text, got, want))
    # A substitution is read wherever it stands: in the value a parameter
    # expansion falls back to, quoted or not, and in an array.
    nested = (
        ('echo "${X:-`a b`}"', [["a", "b"], ["echo", '"${X:-`a b`}"']]),
        ("echo ${X:-`a`}", [["a"], ["echo", "${X:-`a`}"]]),
        ("echo ${X:-${Y:-`a`}}", [["a"], ["echo", "${X:-${Y:-`a`}}"]]),
        ("x=(`a` b)", [["a"], ["x=(`a` b)"]]),
        ("x=(<(a) >(b))", [["a"], ["b"], ["x=(<(a) >(b))"]]),
        ("x=('`a`' \"`b`\")", [["b"], ["x=('`a`' \"`b`\")"]]),
        ("echo ${X:-'`a`'}", [["echo", "${X:-'`a`'}"]]))
    for text, want in nested:
        lexed = S.lex(text, line_index(text))
        got = [[w.raw for w in c.words] for c in lexed.commands]
        if got != want or lexed.problems:
            failures.append("substitutions of %r: %r %r, wanted %r" % (text, got, lexed.problems, want))
    # A case opens after the words that open a compound command as it does
    # at the start of a line: its patterns are not commands.
    cases = (
        ('while read x; do case "$x" in a) b ;; c|d) e ;; esac; done', [["while", "read", "x"], ["do", "case", '"$x"', "in"], ["b"], ["e"], ["done"]]),
        ("if x; then case y in (a) b ;; esac; fi", [["if", "x"], ["then", "case", "y", "in"], ["b"], ["fi"]]),
        ("{ case y in a) b ;; esac; }", [["{", "case", "y", "in"], ["b"], ["}"]]),
        ("f() { case $1 in a) b ;; esac; }; f", [["f"], ["{", "case", "$1", "in"], ["b"], ["}"], ["f"]]),
        ("echo case y in a", [["echo", "case", "y", "in", "a"]]))
    for text, want in cases:
        lexed = S.lex(text, line_index(text))
        got = [[w.raw for w in c.words] for c in lexed.commands]
        if got != want or lexed.problems:
            failures.append("case in %r: %r %r, wanted %r" % (text, got, lexed.problems, want))
    for failure in failures:
        print("FAIL: shell_words: " + failure, file=sys.stderr)
    total = len(SCRIPTS) + len(PROBLEMS) + 25 + len(splitting) + len(conditionals) + len(scopes) + len(nested) + len(cases)
    print("shell_words tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

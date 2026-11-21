"""Crafted cases for scripts/lib/workflow_yaml.py, run by
scripts/check-workflow-pins-tests.sh.

Each read pins the whole tree the reader returns: every node's kind, value,
line, style, comment and the lines a folded value came from. Each refusal
pins its line and its message. Run with `python3 -I -B`.
"""

import os
import sys

if __name__ == "__main__":
    # Run as a script under -I, which puts no directory on the path: the
    # modules beside this one are found here.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import workflow_yaml as Y


def dump(node):
    """A node as nested tuples: ("s", value, line, style, [comment], [breaks]),
    ("m", line, flow, pairs) or ("q", line, flow, items)."""
    if isinstance(node, Y.Scalar):
        out = ["s", node.value, node.line, node.style]
        if node.comment is not None:
            out.append(("comment", node.comment))
        if len(node.breaks) > 1 or node.breaks[0] != (0, node.line):
            out.append(("breaks", node.breaks))
        return tuple(out)
    if isinstance(node, Y.Mapping):
        return ("m", node.line, node.flow, [(dump(k), dump(v)) for k, v in node.pairs])
    return ("q", node.line, node.flow, [dump(i) for i in node.items])


READS = [
  ('flow key with an empty value', 'a: {b:}\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('m', 1, True, [(('s', 'b', 1, 'plain'), ('s', '', 1, 'null'))]))])),
  ('quoted comment without space', 'a: "x" #v1\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'x', 1, 'double', ('comment', 'v1')))])),
  ('plain comment without space after the hash', 'a: one #note\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one', 1, 'plain', ('comment', 'note')))])),
  ('hash before a colon', 'a #b: c\n',
   ('s', 'a', 1, 'plain', ('comment', 'b: c'))),
  ('hash inside a key', 'x#y: z\n',
   ('m', 1, False, [(('s', 'x#y', 1, 'plain'), ('s', 'z', 1, 'plain'))])),
  ('dash key', '-a: b\n',
   ('m', 1, False, [(('s', '-a', 1, 'plain'), ('s', 'b', 1, 'plain'))])),
  ('anchor on a compact sequence', 'a: &x\n- b\nc: *x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 2, False, [('s', 'b', 2, 'plain')])), (('s', 'c', 3, 'plain'), ('q', 2, False, [('s', 'b', 2, 'plain')]))])),
  ('anchor at the end', '- &a\n',
   ('q', 1, False, [('s', '', 1, 'null')])),
  ('anchor before the next item', '- &a\n- b\n',
   ('q', 1, False, [('s', '', 1, 'null'), ('s', 'b', 2, 'plain')])),
  ('single quoted backslash at line end', "a: 'x\\\n  y'\n",
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'x\\ y', 1, 'single', ('breaks', [(0, 1), (3, 2)])))])),
  ('double quoted escaped break without space', 'a: "a\\\n  b"\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'ab', 1, 'double', ('breaks', [(0, 1), (1, 2)])))])),
  ('double quoted escaped backslash at line end', 'a: "a\\\\\n  b"\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'a\\ b', 1, 'double', ('breaks', [(0, 1), (3, 2)])))])),
  ('double quoted trailing spaces', 'a: "a  \n  b"\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'a b', 1, 'double', ('breaks', [(0, 1), (2, 2)])))])),
  ('flow comment at line start', 'a: [b,\n# c\n  d]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b', 1, 'plain'), ('s', 'd', 3, 'plain')]))])),
  ('flow item at column 0', 'a: [b,\nc]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b', 1, 'plain'), ('s', 'c', 2, 'plain')]))])),
  ('empty flow inside flow', 'a: [[], {}, b]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('q', 1, True, []), ('m', 1, True, []), ('s', 'b', 1, 'plain')]))])),
  ('flow key colon at line end', 'a: {b:\n  c}\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('m', 1, True, [(('s', 'b', 1, 'plain'), ('s', 'c', 2, 'plain'))]))])),
  ('flow scalar then comment', 'a: [b #c\n  ]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b', 1, 'plain')]))])),
  ('sequence item continued', '- a\n   - b\n',
   ('q', 1, False, [('s', 'a - b', 1, 'plain', ('breaks', [(0, 1), (2, 2)]))])),
  ('flow scalar with a space', 'a: [b c]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b c', 1, 'plain')]))])),
  ('empty document', '',
   ('m', 1, False, [])),
  ('comments and blank lines only', '# c\n\n  # d\n',
   ('m', 1, False, [])),
  ('document marker', '--- # start\na: 1\n',
   ('m', 2, False, [(('s', 'a', 2, 'plain'), ('s', '1', 2, 'plain'))])),
  ('bom', '\ufeffa: 1\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '1', 1, 'plain'))])),
  ('crlf', 'a: 1\r\nb:\r\n  - x\r\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '1', 1, 'plain')), (('s', 'b', 2, 'plain'), ('q', 3, False, [('s', 'x', 3, 'plain')]))])),
  ('nested block', 'a:\n  b: c\n  d:\n    - e\n    - f: g\n      h: i\n  j: k\nl: m\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('m', 2, False, [(('s', 'b', 2, 'plain'), ('s', 'c', 2, 'plain')), (('s', 'd', 3, 'plain'), ('q', 4, False, [('s', 'e', 4, 'plain'), ('m', 5, False, [(('s', 'f', 5, 'plain'), ('s', 'g', 5, 'plain')), (('s', 'h', 6, 'plain'), ('s', 'i', 6, 'plain'))])])), (('s', 'j', 7, 'plain'), ('s', 'k', 7, 'plain'))])), (('s', 'l', 8, 'plain'), ('s', 'm', 8, 'plain'))])),
  ('compact sequence under a key', 'steps:\n- run: a\n  name: b\n- x\nnext: y\n',
   ('m', 1, False, [(('s', 'steps', 1, 'plain'), ('q', 2, False, [('m', 2, False, [(('s', 'run', 2, 'plain'), ('s', 'a', 2, 'plain')), (('s', 'name', 3, 'plain'), ('s', 'b', 3, 'plain'))]), ('s', 'x', 4, 'plain')])), (('s', 'next', 5, 'plain'), ('s', 'y', 5, 'plain'))])),
  ('sequence item on its own lines', 'a:\n  -\n    b: c\n  -\n  - d\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 2, False, [('m', 3, False, [(('s', 'b', 3, 'plain'), ('s', 'c', 3, 'plain'))]), ('s', '', 4, 'null'), ('s', 'd', 5, 'plain')]))])),
  ('nested sequences', '- - a\n  - b\n- c\n',
   ('q', 1, False, [('q', 1, False, [('s', 'a', 1, 'plain'), ('s', 'b', 2, 'plain')]), ('s', 'c', 3, 'plain')])),
  ('keys with spaces and quotes', '"uses" : a\n\'b c\': d\ne f : g\n"h": \n',
   ('m', 1, False, [(('s', 'uses', 1, 'double'), ('s', 'a', 1, 'plain')), (('s', 'b c', 2, 'single'), ('s', 'd', 2, 'plain')), (('s', 'e f', 3, 'plain'), ('s', 'g', 3, 'plain')), (('s', 'h', 4, 'double'), ('s', '', 4, 'null'))])),
  ('key at end of line then null', 'a:\nb: c\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '', 1, 'null')), (('s', 'b', 2, 'plain'), ('s', 'c', 2, 'plain'))])),
  ('plain over lines', 'a: one\n  two\n\n  three\n   four\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one two\nthree four', 1, 'plain', ('breaks', [(0, 1), (4, 2), (8, 4), (14, 5)]))), (('s', 'b', 6, 'plain'), ('s', 'x', 6, 'plain'))])),
  ('plain with comment', 'a: one # note\nb: x#y\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one', 1, 'plain', ('comment', 'note'))), (('s', 'b', 2, 'plain'), ('s', 'x#y', 2, 'plain'))])),
  ('double quoted escapes', 'a: "t\\tn\\nx\\x41u\\u00e9U\\U0001F600 \\" \\\\ \\/ \\0\\a\\b\\v\\f\\r\\e\\N\\_\\L\\P\\ x"\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 't\tn\nxAuéU😀 " \\ / \x00\x07\x08\x0b\x0c\r\x1b\x85\xa0\u2028\u2029 x', 1, 'double'))])),
  ('double quoted folding', 'a: "one\n  two\n\n  three \\\n  four"\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one two\nthree four', 1, 'double', ('breaks', [(0, 1), (4, 2), (8, 4), (14, 5)])))])),
  ('double quoted escaped tab', 'a: "x\\\ty"\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'x\ty', 1, 'double'))])),
  ('single quoted', "a: 'it''s'\nb: 'one\n  two'\n",
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', "it's", 1, 'single')), (('s', 'b', 2, 'plain'), ('s', 'one two', 2, 'single', ('breaks', [(0, 2), (4, 3)])))])),
  ('quoted with comment', 'a: "x" # v1\nb: \'y\'   #  c  \n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'x', 1, 'double', ('comment', 'v1'))), (('s', 'b', 2, 'plain'), ('s', 'y', 2, 'single', ('comment', 'c')))])),
  ('literal block', 'a: |\n  one\n    two\n\n  three\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one\n  two\n\nthree\n', 2, 'literal', ('breaks', [(0, 2), (4, 3), (10, 4), (11, 5)]))), (('s', 'b', 6, 'plain'), ('s', 'x', 6, 'plain'))])),
  ('literal strip', 'a: |-\n  one\n\n\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one', 2, 'literal')), (('s', 'b', 5, 'plain'), ('s', 'x', 5, 'plain'))])),
  ('literal keep', 'a: |+\n  one\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one\n', 2, 'literal')), (('s', 'b', 3, 'plain'), ('s', 'x', 3, 'plain'))])),
  ('literal indent indicator', 'a: |2\n    one\n  two\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '  one\ntwo\n', 2, 'literal', ('breaks', [(0, 2), (6, 3)]))), (('s', 'b', 4, 'plain'), ('s', 'x', 4, 'plain'))])),
  ('literal indicators reversed', 'a: |-2\n    one\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '  one', 2, 'literal')), (('s', 'b', 3, 'plain'), ('s', 'x', 3, 'plain'))])),
  ('literal header comment', 'a: | # c\n  one\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one\n', 2, 'literal'))])),
  ('empty literal', 'a: |\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '', 1, 'literal')), (('s', 'b', 2, 'plain'), ('s', 'x', 2, 'plain'))])),
  ('folded block', 'a: >\n  one\n  two\n\n  three\n    more\n  four\nb: x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one two\nthree\n  more\nfour\n', 2, 'folded', ('breaks', [(0, 2), (4, 3), (8, 5), (14, 6), (21, 7)]))), (('s', 'b', 8, 'plain'), ('s', 'x', 8, 'plain'))])),
  ('folded leading empty', 'a: >\n\n  one\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '\none\n', 2, 'folded', ('breaks', [(1, 3)])))])),
  ('block in sequence', '- |\n  x\n- y\n',
   ('q', 1, False, [('s', 'x\n', 2, 'literal'), ('s', 'y', 3, 'plain')])),
  ('flow sequence', 'a: [b, \'c\', "d", [e], {f: g}]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b', 1, 'plain'), ('s', 'c', 1, 'single'), ('s', 'd', 1, 'double'), ('q', 1, True, [('s', 'e', 1, 'plain')]), ('m', 1, True, [(('s', 'f', 1, 'plain'), ('s', 'g', 1, 'plain'))])]))])),
  ('flow mapping', 'a: {b: c, d: [e, f], g, h: }\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('m', 1, True, [(('s', 'b', 1, 'plain'), ('s', 'c', 1, 'plain')), (('s', 'd', 1, 'plain'), ('q', 1, True, [('s', 'e', 1, 'plain'), ('s', 'f', 1, 'plain')])), (('s', 'g', 1, 'plain'), ('s', '', 1, 'null')), (('s', 'h', 1, 'plain'), ('s', '', 1, 'null'))]))])),
  ('flow empty', 'a: []\nb: {}\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [])), (('s', 'b', 2, 'plain'), ('m', 2, True, []))])),
  ('flow over lines', 'a: [b,\n  c, # note\n  d]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b', 1, 'plain'), ('s', 'c', 2, 'plain'), ('s', 'd', 3, 'plain')]))])),
  ('flow with comment after', 'a: [b] # end\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b', 1, 'plain')]))])),
  ('flow url scalar', 'a: [http://x:1/y]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'http://x:1/y', 1, 'plain')]))])),
  ('flow colon in scalar', 'a: {b:c}\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('m', 1, True, [(('s', 'b:c', 1, 'plain'), ('s', '', 1, 'null'))]))])),
  ('anchor and alias', 'a: &x\n  b: c\nd: *x\ne: &y f\ng: *y # again\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('m', 2, False, [(('s', 'b', 2, 'plain'), ('s', 'c', 2, 'plain'))])), (('s', 'd', 3, 'plain'), ('m', 2, False, [(('s', 'b', 2, 'plain'), ('s', 'c', 2, 'plain'))])), (('s', 'e', 4, 'plain'), ('s', 'f', 4, 'plain')), (('s', 'g', 5, 'plain'), ('s', 'f', 4, 'plain'))])),
  ('anchor on sequence item', '- &a x\n- *a\n- &b\n  c: d\n',
   ('q', 1, False, [('s', 'x', 1, 'plain'), ('s', 'x', 1, 'plain'), ('m', 4, False, [(('s', 'c', 4, 'plain'), ('s', 'd', 4, 'plain'))])])),
  ('anchor then nothing', 'a: &x\nb: *x\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', '', 1, 'null')), (('s', 'b', 2, 'plain'), ('s', '', 1, 'null'))])),
  ('flow anchor and alias', 'a: [&x b, *x]\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 1, True, [('s', 'b', 1, 'plain'), ('s', 'b', 1, 'plain')]))])),
  ('value with indicators inside', 'a: b-c ?d :e\nb: -1\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'b-c ?d :e', 1, 'plain')), (('s', 'b', 2, 'plain'), ('s', '-1', 2, 'plain'))])),
  ('deep indentation', 'jobs:\n    a:\n        b: c\n',
   ('m', 1, False, [(('s', 'jobs', 1, 'plain'), ('m', 2, False, [(('s', 'a', 2, 'plain'), ('m', 3, False, [(('s', 'b', 3, 'plain'), ('s', 'c', 3, 'plain'))]))]))])),
  ('tab inside a value', 'a: b\tc\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'b\tc', 1, 'plain'))])),
  ('key with url value', 'a: http://x/y\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'http://x/y', 1, 'plain'))])),
  ('hash without space', 'a: b#c\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'b#c', 1, 'plain'))])),
  ('top-level sequence', '- a\n- b\n',
   ('q', 1, False, [('s', 'a', 1, 'plain'), ('s', 'b', 2, 'plain')])),
  ('top-level scalar', 'just text\n',
   ('s', 'just text', 1, 'plain')),
  ('mapping after compact sequence', 'a:\n- b\nc: d\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('q', 2, False, [('s', 'b', 2, 'plain')])), (('s', 'c', 3, 'plain'), ('s', 'd', 3, 'plain'))])),
  ('line_at', 'a: >\n  one\n  two\n',
   ('m', 1, False, [(('s', 'a', 1, 'plain'), ('s', 'one two\n', 2, 'folded', ('breaks', [(0, 2), (4, 3)])))])),
]
REFUSALS = [
  ('explicit-looking key with a tab in a mapping', 'a: 1\n?\tb: c\n', 2, 'a line in a mapping that is not a key'),
  ('flow not closed on the last line', 'a: [b', 1, 'a value in brackets that does not close'),
  ('sequence then key', '- a\nb: c\n', 2, 'a line outside the structure above it'),
  ('quoted key followed by text', '"a" x\n', 1, 'text after a quoted value: x'),
  ('dash colon', '-: x\n', 1, 'a colon and a space inside a plain value: quote the value'),
  ('explicit key tab with colon', '?\ta: b\n', 1, 'an explicit key (`? key`): write the key before its colon'),
  ('explicit-looking key in a mapping', 'a: 1\n? b: c\n', 2, 'a line in a mapping that is not a key'),
  ('colon first', ': x\n', 1, 'a value that starts with the indicator :'),
  ('sequence over-indented after flow', 'a: [1]\n  - b\n', 2, 'indentation that matches no key above it'),
  ('item over-indented after flow', '- [a]\n   - b\n', 2, 'indentation that matches no item above it'),
  ('dash at end', 'a: -\n', 1, 'a value that starts with the indicator -'),
  ('dash tab', 'a: -\tb\n', 1, 'a value that starts with the indicator -'),
  ('flow error on line 2', 'a: [b,\n  c}\n', 2, "a value in brackets that is not YAML near '}'"),
  ('flow scalar continued at the end of the file', 'a: [b\n  c]', 1, 'a value in brackets continued on the next line'),
  ('tag after a key', '!t a: b\n', 1, 'a YAML tag'),
  ('comment line inside a plain value', 'a: one\n  # c\n  two\n', 3, 'indentation that matches no key above it'),
  ('folded scalar less indented later', 'a: >\n    x\n    y\n  z\n', 4, 'indentation that matches no key above it'),
  ('empty second document', 'a: 1\n---\n', 2, 'more than one YAML document'),
  ('directive', '%YAML 1.2\na: 1\n', 1, 'a YAML directive'),
  ('text after document marker', '--- x\na: 1\n', 1, 'text after the document marker: x'),
  ('second document', 'a: 1\n---\nb: 2\n', 2, 'more than one YAML document'),
  ('document end', 'a: 1\n...\n', 2, 'more than one YAML document'),
  ('line outside', 'a: 1\n b: 2\n', 2, 'a colon and a space inside a plain value: quote the value'),
  ('explicit key', '? a\n: b\n', 1, 'an explicit key (`? key`): write the key before its colon'),
  ('explicit key tab', '?\ta\n', 1, 'an explicit key (`? key`): write the key before its colon'),
  ('explicit key alone', '?\n', 1, 'an explicit key (`? key`): write the key before its colon'),
  ('anchor on key', '&a b: c\n', 1, 'an anchor on a key'),
  ('alias as key', 'a: &x 1\n*x : 2\n', 2, 'an alias as a key'),
  ('tag on key', '!t a: b\n', 1, 'a YAML tag'),
  ('flow key', '[a]: b\n', 1, 'a key that is not a scalar'),
  ('flow map key', '{a: b}: c\n', 1, 'a key that is not a scalar'),
  ('merge key', '<<: {a: b}\n', 1, 'a merge key (`<<`)'),
  ('duplicate key', 'a: 1\na: 2\n', 2, 'the key a twice in one mapping'),
  ('not a key in mapping', 'a: 1\nb\n', 2, 'a line in a mapping that is not a key'),
  ('indentation in mapping', 'a: 1\n  b: 2\n', 2, 'a colon and a space inside a plain value: quote the value'),
  ('tag in value', 'a: !!str b\n', 1, 'a YAML tag'),
  ('tag in value after anchor', 'a: &x !t b\n', 1, 'a YAML tag'),
  ('tag as item', '- !t b\n', 1, 'a YAML tag'),
  ('tab indentation', 'a:\n\tb: c\n', 2, 'a tab in the indentation'),
  ('anchor with no name', 'a: & b\n', 1, 'an anchor with no name'),
  ('alias to nothing', 'a: *nope\n', 1, 'an alias to no anchor above it: *nope'),
  ('text after alias', 'a: &x 1\nb: *x y\n', 2, 'text after an alias: y'),
  ('indicator start percent', 'a: %x\n', 1, 'a value that starts with the indicator %'),
  ('indicator start at', 'a: @x\n', 1, 'a value that starts with the indicator @'),
  ('indicator start backtick', 'a: `x`\n', 1, 'a value that starts with the indicator `'),
  ('indicator start dash space', 'a: - b\n', 1, 'a value that starts with the indicator -'),
  ('indicator start colon', 'a: : b\n', 1, 'a value that starts with the indicator :'),
  ('indicator start question', 'a: ? b\n', 1, 'a value that starts with the indicator ?'),
  ('colon in plain', 'a: b: c\n', 1, 'a colon and a space inside a plain value: quote the value'),
  ('colon at end of plain', 'a: b:\n', 1, 'a colon and a space inside a plain value: quote the value'),
  ('colon in plain continuation', 'a: b\n  c: d\n', 2, 'a colon and a space inside a plain value: quote the value'),
  ('text after quoted', 'a: "b" c\n', 1, 'text after a quoted value: c'),
  ('quote not closed', 'a: "b\n', 1, 'a quoted value that does not close'),
  ('single not closed', "a: 'b\n  c\n", 1, 'a quoted value that does not close'),
  ('bad escape', 'a: "\\q"\n', 1, 'an escape that is not YAML: \\q'),
  ('bad hex escape', 'a: "\\xZZ"\n', 1, 'an escape that is not YAML: \\xZZ'),
  ('short hex escape', 'a: "\\u12"\n', 1, 'an escape that is not YAML: \\u12"'),
  ('block header bad', 'a: |x\n', 1, 'text after a block scalar header: x'),
  ('block header both chomps', 'a: |+-\n', 1, 'a block scalar header that is not YAML'),
  ('text after block header', 'a: | x\n', 1, 'text after a block scalar header: x'),
  ('flow not closed', 'a: [b, c\n', 2, 'a value in brackets that does not close'),
  ('flow key in sequence', 'a: [b: c]\n', 1, 'a key inside a sequence in brackets'),
  ('flow explicit key', 'a: {? b: c}\n', 1, 'an explicit key (`? key`): write the key before its colon'),
  ('flow nonscalar key', 'a: {[b]: c}\n', 1, 'a key that is not a scalar'),
  ('flow duplicate key', 'a: {b: 1, b: 2}\n', 1, 'the key b twice in one mapping'),
  ('flow tag', 'a: [!t b]\n', 1, 'a YAML tag'),
  ('flow alias to nothing', 'a: [*x]\n', 1, 'an alias to no anchor above it: *x'),
  ('flow anchor no name', 'a: [& b]\n', 1, 'an anchor with no name'),
  ('flow empty scalar', 'a: [b, , c]\n', 1, 'a value in brackets that is not YAML'),
  ('flow scalar continued', 'a: [b\n  c]\n', 1, 'a value in brackets continued on the next line'),
  ('text after flow', 'a: [b] c\n', 1, 'text after a value in brackets: c'),
  ('quoted key over lines', '"a\nb": c\n', 2, 'text after a quoted value: : c'),
]


def main():
    failures = []
    for name, text, want in READS:
        try:
            got = dump(Y.read(text))
        except Y.Refusal as e:
            got = ("refused", e.line, e.message)
        if got != want:
            failures.append("%s: read %r, wanted %r" % (name, got, want))
    for name, text, line, message in REFUSALS:
        try:
            got = ("read", dump(Y.read(text)))
        except Y.Refusal as e:
            got = (e.line, e.message)
        if got != (line, message):
            failures.append("%s: got %r, wanted %r" % (name, got, (line, message)))
    folded = Y.read("a: >\n  one\n  two\n\n  three\n").get("a")
    for offset, line in ((0, 2), (3, 2), (4, 3), (7, 3), (8, 5), (100, 5)):
        if folded.line_at(offset) != line:
            failures.append("line_at(%d): %d, wanted %d" % (offset, folded.line_at(offset), line))
    doc = Y.read("a: &x\n  b: c\nd: *x\n")
    seen = [dump(n) for n in Y.walk(doc)]
    if len(seen) != 6:
        failures.append("walk: %d nodes, wanted 6 (an aliased node once): %r" % (len(seen), seen))
    if doc.get("nope") is not None or doc.key("nope") is not None:
        failures.append("get and key of a missing key are not None")
    if doc.key("d").line != 3:
        failures.append("key(d) is not the key on line 3")
    if str(Y.Refusal(3, "a message")) != "a message":
        failures.append("a refusal's text is not its message")
    for failure in failures:
        print("FAIL: workflow_yaml: " + failure, file=sys.stderr)
    total = len(READS) + len(REFUSALS) + 10
    print("workflow_yaml tests: %d passed, %d failed" % (total - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

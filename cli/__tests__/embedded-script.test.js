/**
 * JavaScript embedded in markup.
 *
 * `isInsideJavaScriptNonCode` tracks quotes and comments from the start of the
 * source, which is right for a .js file and wrong for a page. HTML and PHP are
 * full of unbalanced quotes — `value='English'`, an apostrophe in a sentence —
 * so by the time the walk reaches a <script> block it believes it is inside a
 * string and dismisses every match in it.
 *
 * That silently lost DVWA's DOM XSS exercise: a real document.write() fed from
 * location.href stopped being reported at all.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { isInsideJavaScriptNonCode } from '../agents/base-agent.js';

const at = (source, needle) => isInsideJavaScriptNonCode(source, source.indexOf(needle));

describe('script blocks inside markup', () => {
  it('sees code in a script block that follows unbalanced quotes', () => {
    const page = [
      "<p>Here's a sentence with an apostrophe.</p>",
      "<option value='English'>English</option>",
      '<script>',
      '  document.write(location.hash);',
      '</script>',
    ].join('\n');

    assert.equal(at(page, 'document.write'), false);
  });

  it('sees code in a script block with attributes on the tag', () => {
    const page = "<div class='x'>it's fine</div>\n<script type=\"text/javascript\">\n  document.write(location.hash);\n</script>";
    assert.equal(at(page, 'document.write'), false);
  });

  it('still recognises a string inside the script block', () => {
    const page = "<p>it's markup</p>\n<script>\n  var a = \"document.write(x)\";\n</script>";
    assert.equal(at(page, 'document.write'), true);
  });

  it('still recognises a comment inside the script block', () => {
    const page = "<p>it's markup</p>\n<script>\n  // document.write(x)\n</script>";
    assert.equal(at(page, 'document.write'), true);
  });

  it('does not carry state across a closed script block', () => {
    // An earlier block that opened a string and closed it says nothing about
    // where a later match sits.
    const page = [
      '<script>',
      '  var a = "unterminated-looking \\' + "'" + '";',
      '</script>',
      '<p>text</p>',
      '<script>',
      '  document.write(location.hash);',
      '</script>',
    ].join('\n');

    assert.equal(at(page, 'document.write(location'), false);
  });
});

describe('plain script files are unchanged', () => {
  it('sees ordinary code', () => {
    assert.equal(at('var lang = location.hash;\ndocument.write(lang);\n', 'document.write'), false);
  });

  it('sees a string as a string', () => {
    assert.equal(at('var a = "document.write(x)";\n', 'document.write'), true);
  });

  it('sees a comment as a comment', () => {
    assert.equal(at('// document.write(x)\n', 'document.write'), true);
  });
});

/* Safe, dependency-free, LIMITED Markdown presentation for optional Groq advice.
 * AI text is untrusted. Never use innerHTML/insertAdjacentHTML or execute it.
 * Supported: headings, paragraphs, bold/italic/code, lists, blockquotes,
 * horizontal rules, fenced code blocks, and pipe tables with separator rows.
 */
'use strict';
(() => {
  const knownHeadings = /^(Findings|Evidence|Possible weaknesses|Mitigation|Mitigations|Validation|Limitations|Recommendations|Risk interpretation|Suggested features|Summary|Next steps)\s*:?$/i;
  const el = (tag, className = '') => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  };
  function inline(parent, raw) {
    const value = String(raw || '');
    // Inline formatting is assembled exclusively from text nodes and DOM elements.
    const token = /(\*\*[^*\n]+\*\*|__[^_\n]+__|`[^`\n]+`|\*[^*\n]+\*)/g;
    let from = 0;
    for (const m of value.matchAll(token)) {
      if (m.index > from) parent.append(document.createTextNode(value.slice(from, m.index)));
      let tag = 'em', content = m[0].slice(1, -1);
      if (m[0].startsWith('**') || m[0].startsWith('__')) {
        tag = 'strong'; content = m[0].slice(2, -2);
      } else if (m[0].startsWith('`')) {
        tag = 'code';
      }
      const formatted = el(tag);
      formatted.textContent = content;
      parent.append(formatted);
      from = m.index + m[0].length;
    }
    if (from < value.length) parent.append(document.createTextNode(value.slice(from)));
  }
  function pipeCells(line) {
    const s = line.trim().replace(/^\|/, '').replace(/\|$/, '');
    // Backslash-escaped pipes are text within a cell, not separators.
    return s.split(/(?<!\\)\|/).map(x => x.replace(/\\\|/g, '|').trim());
  }
  function isDivider(line) {
    const cells = pipeCells(line);
    return cells.length > 1 && cells.every(x => /^:?-{3,}:?$/.test(x));
  }
  function tableAt(lines, i) {
    if (i + 1 >= lines.length || !lines[i].includes('|') || !isDivider(lines[i + 1])) return false;
    const headers = pipeCells(lines[i]);
    const separators = pipeCells(lines[i + 1]);
    return headers.length >= 2 && headers.length <= 8 && headers.length === separators.length;
  }
  function addTable(root, lines, start) {
    const headings = pipeCells(lines[start]);
    const frame = el('div', 'groq-table-scroll');
    const table = el('table', 'groq-evidence-table');
    const thead = el('thead');
    const head = el('tr');
    for (const value of headings) {
      const cell = el('th'); cell.scope = 'col'; inline(cell, value); head.append(cell);
    }
    thead.append(head); table.append(thead);
    const body = el('tbody');
    let at = start + 2, count = 0;
    while (at < lines.length && lines[at].trim().includes('|') && count < 40) {
      const values = pipeCells(lines[at]);
      if (values.length !== headings.length || isDivider(lines[at])) break;
      const row = el('tr');
      for (const value of values) { const cell = el('td'); inline(cell, value); row.append(cell); }
      body.append(row);
      at++; count++;
    }
    table.append(body); frame.append(table); root.append(frame);
    return at;
  }
  function headingAt(line) {
    const h = line.match(/^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$/);
    if (h) return h[1];
    const boldOnly = line.match(/^\s*(?:\*\*(.*?)\*\*|__(.*?)__)\s*:?\s*$/);
    if (boldOnly) return boldOnly[1] || boldOnly[2];
    if (knownHeadings.test(line.trim())) return line.trim().replace(/:$/, '');
    return null;
  }
  function isList(line) { return /^\s{0,4}(?:[-*+]\s+|\d+[.)]\s+)/.test(line); }
  function isBlock(line) {
    return !line.trim() || /^\s*```/.test(line) || /^\s{0,3}>\s?/.test(line) ||
      /^\s*(?:---+|\*\*\*+)\s*$/.test(line) || headingAt(line) !== null || isList(line);
  }
  function render(text) {
    const root = el('div', 'groq-rich-content');
    const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n').slice(0, 350);
    let i = 0;
    while (i < lines.length) {
      const line = lines[i].trim();
      if (!line) { i++; continue; }
      if (/^```/.test(line)) {
        const code = el('pre', 'groq-code-block');
        const inner = el('code');
        const body = [];
        i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) body.push(lines[i++]);
        if (i < lines.length) i++;
        inner.textContent = body.join('\n'); code.append(inner); root.append(code);
        continue;
      }
      if (tableAt(lines, i)) { i = addTable(root, lines, i); continue; }
      const heading = headingAt(line);
      if (heading !== null) {
        const h = el('h3', 'groq-section-title');
        inline(h, heading); root.append(h); i++; continue;
      }
      if (/^(?:---+|\*\*\*+)$/.test(line)) { root.append(el('hr')); i++; continue; }
      if (/^>\s?/.test(line)) {
        const quote = el('blockquote', 'groq-quote');
        while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
          const paragraph = el('p'); inline(paragraph, lines[i++].replace(/^\s*>\s?/, '')); quote.append(paragraph);
        }
        root.append(quote); continue;
      }
      if (isList(lines[i])) {
        const ordered = /^\s{0,4}\d+[.)]\s+/.test(lines[i]);
        const list = el(ordered ? 'ol' : 'ul');
        while (i < lines.length && isList(lines[i]) && /^\s{0,4}\d+[.)]\s+/.test(lines[i]) === ordered) {
          const item = el('li');
          inline(item, lines[i].replace(/^\s{0,4}(?:[-*+]\s+|\d+[.)]\s+)/, ''));
          list.append(item); i++;
        }
        root.append(list); continue;
      }
      // A paragraph can contain soft line wraps. Do not absorb a table or heading.
      const paragraph = [];
      while (i < lines.length && !isBlock(lines[i]) && !tableAt(lines, i)) {
        paragraph.push(lines[i++].trim());
      }
      if (!paragraph.length) { // malformed separators should remain visible as text
        paragraph.push(lines[i++].trim());
      }
      const p = el('p'); inline(p, paragraph.join(' ')); root.append(p);
    }
    return root;
  }
  // One read-only rendering function; no remote scripts, no HTML interpretation.
  window.FortressGroqMarkdown = Object.freeze({render});
})();

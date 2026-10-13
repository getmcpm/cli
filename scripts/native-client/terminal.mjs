// A bounded current screen, rather than ANSI-stripped history containing old prompts.
export class TerminalScreen {
  constructor(width = 120, height = 40) {
    this.width = width; this.height = height; this.row = 0; this.col = 0; this.pending = ''; this.wrapPending = false;
    this.rows = Array.from({ length: height }, () => []);
  }
  feed(text) {
    text = this.pending + text; this.pending = '';
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === '\x1b') {
        const tail = text.slice(i);
        if (tail.startsWith('\x1b[')) {
          const m = /^\x1b\[([0-?]*)([ -/]*)([@-~])/.exec(tail);
          if (!m) { this.pending = tail; break; }
          const p = m[1].replace(/^\?/, '').split(';').map(v => Number(v) || 0), n = p[0] || 1;
          if ('Hf'.includes(m[3])) { this.row = (p[0] || 1) - 1; this.col = (p[1] || 1) - 1; }
          else if (m[3] === 'A') this.row -= n;
          else if (m[3] === 'B') this.row += n;
          else if (m[3] === 'C') this.col += n;
          else if (m[3] === 'D') this.col -= n;
          else if (m[3] === 'G') this.col = n - 1;
          else if (m[3] === 'J') {
            if (p[0] === 2 || p[0] === 3) this.rows = Array.from({ length: this.height }, () => []);
            else if (p[0] === 0) { this.rows[this.row].splice(this.col); for (let r = this.row + 1; r < this.height; r++) this.rows[r] = []; }
          } else if (m[3] === 'K') {
            if (p[0] === 2) this.rows[this.row] = [];
            else if (p[0] === 1) this.rows[this.row].fill(' ', 0, this.col + 1);
            else this.rows[this.row].splice(this.col);
          } else if (m[3] === 's') this.saved = [this.row, this.col];
          else if (m[3] === 'u' && this.saved) [this.row, this.col] = this.saved;
          this.row = Math.max(0, Math.min(this.height - 1, this.row)); this.col = Math.max(0, Math.min(this.width - 1, this.col));
          if ('HfABCDGJu'.includes(m[3])) this.wrapPending = false;
          i += m[0].length - 1; continue;
        }
        if (tail.startsWith('\x1b]')) {
          const m = /^\x1b\][\s\S]*?(?:\x07|\x1b\\)/.exec(tail);
          if (!m) { this.pending = tail; break; }
          i += m[0].length - 1; continue;
        }
        if (tail.length < 2) { this.pending = tail; break; }
        i++; continue;
      }
      if (ch === '\r') { this.col = 0; this.wrapPending = false; }
      else if (ch === '\n') { this.wrapPending = false; this.row++; if (this.row >= this.height) { this.rows.shift(); this.rows.push([]); this.row--; } }
      else if (ch === '\b') this.col = Math.max(0, this.col - 1);
      else if (ch === '\t') this.col = Math.min(this.width - 1, (Math.floor(this.col / 8) + 1) * 8);
      else if (ch >= ' ') {
        if (this.wrapPending) { this.col = 0; this.row++; if (this.row >= this.height) { this.rows.shift(); this.rows.push([]); this.row--; } this.wrapPending = false; }
        this.rows[this.row][this.col] = ch;
        if (this.col === this.width - 1) this.wrapPending = true; else this.col++;
      }
    }
    if (this.pending.length > 4096) throw Error('terminal escape budget exceeded');
  }
  get text() { return this.rows.map(r => Array.from({ length: r.length }, (_, i) => r[i] ?? ' ').join('').trimEnd()).join('\n').trimEnd(); }
}

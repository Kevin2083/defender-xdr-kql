require('./node_modules/@kusto/language-service-next/bridge.js');
require('./node_modules/@kusto/language-service-next/Kusto.Language.Bridge.js');
const fs = require('fs'), path = require('path');
const K = Kusto.Language, S = K.Symbols;
const schema = require('./schema.js');
const tables = Object.entries(schema).map(([n,s]) => new S.TableSymbol.$ctor7(n, "(" + s + ")", null));
const db = new S.DatabaseSymbol.$ctor1("hunting", tables, false);
const cl = new S.ClusterSymbol.$ctor1("c", [db], false);
const g = K.GlobalState.Default.WithClusterList([cl]).WithCluster(cl).WithDatabase(db);
const HDR = /^\/\/ (?:(\d+\.\d+) |── (C\d+)\.)/;
const root = process.argv[2]; const verbose = process.argv[3] === '-v';
let total = 0, bad = 0, warn = 0;
for (const f of fs.readdirSync(root, {recursive:true}).filter(x => x.endsWith('.kql')).sort()) {
  const lines = fs.readFileSync(path.join(root, f), 'utf8').split('\n');
  const blocks = []; let cur = null;
  lines.forEach((l, i) => { const m = l.match(HDR); if (m) { cur = {id: m[1]||m[2], title: l.replace(/^\/\/ (── )?/, '').trim(), start: i+1, lines: []}; blocks.push(cur); } if (cur) cur.lines.push(l); });
  for (const b of blocks) {
    total++;
    const q = b.lines.join('\n');
    const code = K.KustoCode.ParseAndAnalyze(q, g);
    const d = code.GetDiagnostics(); const n = System.Array.getCount(d, K.Diagnostic);
    const msgs = [];
    for (let i = 0; i < n; i++) { const x = System.Array.getItem(d, i, K.Diagnostic);
      const lineNo = b.start + q.slice(0, x.Start).split('\n').length - 1;
      msgs.push(`${x.Severity} L${lineNo}: ${x.Message}`); }
    const errs = msgs.filter(m => m.startsWith('Error')); const ws = msgs.filter(m => !m.startsWith('Error'));
    if (errs.length) bad++; if (ws.length) warn++;
    if (errs.length || (verbose && ws.length)) { console.log(`\n[${errs.length ? 'FAIL' : 'warn'}] ${f} :: ${b.title}`); (verbose ? msgs : errs).forEach(m => console.log('   ' + m)); }
  }
}
console.log(`\n==== ${total} queries | ${bad} with errors | ${total-bad} clean | ${warn} with warnings`);

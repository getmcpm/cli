import { appendFile } from 'node:fs/promises';
let text = '';
for await (const chunk of process.stdin) { text += chunk; if (text.length > 65536) throw Error('oversized hook input'); }
const input = JSON.parse(text);
const component = process.argv[2];
await appendFile('/work/markers.jsonl', JSON.stringify({ component, input, pid: process.pid, ppid: process.ppid }) + '\n');
if (component.startsWith('blocker')) console.log(JSON.stringify({ decision: 'block', reason: `offline-fixture-block:${input.prompt}` }));

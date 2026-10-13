import { createServer } from 'node:http';
import { appendFileSync } from 'node:fs';
import assert from 'node:assert/strict';

export async function gateway(work, request) {
  const observations = [];
  const issued = [];
  let results = [];
  let calls = 0;
  let bytes = 0;
  const server = createServer(async (req, res) => {
    try {
      let body = '';
      for await (const chunk of req) { bytes += chunk.length; body += chunk; if (Buffer.byteLength(body) > 1024 * 1024 || bytes > 2 * 1024 * 1024) throw Error('gateway input budget exceeded'); }
      if (++calls > 20) throw Error('gateway request budget exceeded');
      const data = body ? JSON.parse(body) : {};
      const row = { path: req.url, data }; observations.push(row);
      appendFileSync(`${work}/gateway.jsonl`, JSON.stringify(row) + '\n');
      if (req.url?.startsWith('/v1/messages/count_tokens')) { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"input_tokens":100}'); return; }
      if (!req.url?.startsWith('/v1/messages')) { res.writeHead(404); res.end('{}'); return; }
      const title = data.tools?.length === 0 && data.messages?.some(m => m.content?.some?.(c => c.type === 'text' && c.text.startsWith(`<session>\nRun the native fixture ${request.case} check with text ${request.text}.\n</session>`) && c.text.includes('Write the title in the predominant language of the session')));
      let content, done;
      if (title) { row.kind = 'synthetic-session-title'; done = true; content = { type: 'text', text: 'Native fixture check' }; }
      else {
      const completed = (data.messages || []).flatMap(m => Array.isArray(m.content) ? m.content : []).filter(c => c.type === 'tool_result');
      assert.ok(completed.length <= issued.length, 'unissued tool result');
      assert.deepEqual(completed.map(c => c.tool_use_id), issued.slice(0, completed.length).map(c => c.id), 'uncorrelated or duplicate tool result');
      results = completed;
      const step = completed.length;
      done = step >= (['block', 'one-shot'].includes(request.case) ? 2 : 1);
      const desired = request.case === 'block' ? (step ? 'echo' : 'attack') : request.case === 'cancel' ? 'slow' : ['attack', 'warn'].includes(request.case) ? request.case : 'echo';
      const tool = (data.tools || []).find(t => t.name?.endsWith('__' + desired));
      if (!done && !tool) throw Error(`Native ${desired} tool missing from Claude request`);
      content = done ? { type: 'text', text: 'Synthetic gateway observed the native tool result.' }
        : { type: 'tool_use', id: `native-${step}`, name: tool.name, input: { text: request.case === 'one-shot' ? `${request.text}-${step + 1}` : request.text } };
      if (!done) {
        if (issued[step]) assert.deepEqual(content, issued[step], 'changed tool-use retry');
        else issued.push(content);
      }
      }
      const message = { id: 'msg_native_fixture', type: 'message', role: 'assistant', model: data.model, content: [content],
        stop_reason: done ? 'end_turn' : 'tool_use', stop_sequence: null, usage: { input_tokens: 10, output_tokens: 10 } };
      if (!data.stream) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(message)); return; }
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      const event = (type, value) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...value })}\n\n`);
      event('message_start', { message: { ...message, content: [], stop_reason: null, usage: { input_tokens: 10, output_tokens: 0 } } });
      event('content_block_start', { index: 0, content_block: done ? { type: 'text', text: '' } : { ...content, input: {} } });
      event('content_block_delta', { index: 0, delta: done ? { type: 'text_delta', text: content.text } : { type: 'input_json_delta', partial_json: JSON.stringify(content.input) } });
      event('content_block_stop', { index: 0 });
      event('message_delta', { delta: { stop_reason: message.stop_reason, stop_sequence: null }, usage: { output_tokens: 10 } });
      event('message_stop', {}); res.end();
    } catch (e) { observations.push({ error: e.message }); res.writeHead(422, { 'content-type': 'application/json' }); res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: e.message } })); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, observations, get results() { return results; }, close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }) };
}

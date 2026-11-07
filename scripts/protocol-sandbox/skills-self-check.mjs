import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifySkillCapture, assertSkillVerification, assertSkillPair, SKILLS_SPEC } from './skills-verification.mjs';

const uri = 'skill://sample/SKILL.md';
const text = '\uFEFF---\r\nname: sample\r\ndescription: Review changes\r\nmetadata:\r\n  version: "1"\r\n---\r\n雪\r\n';
const files = { [uri]: Buffer.from(text), 'skill://sample/asset.bin': Buffer.from([0, 255, 13, 10]) };
const digest = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const entry = () => ({ uri, frontmatter: { name: 'sample', description: 'Review changes', metadata: { version: '1' } },
  resources: Object.entries(files).map(([uri, bytes]) => ({ uri, size: bytes.length, digest: digest(bytes) })) });
function sample() {
  const wire = [];
  function add(id, method, result, resource = uri, params = {}) {
    wire.push({ direction: 'to-server', message: { jsonrpc: '2.0', id, method, params: { uri: resource, ...params } } },
      { direction: 'from-server', message: { jsonrpc: '2.0', id, result: { resultType: 'complete', ttlMs: 0, cacheScope: 'private', ...result } } });
  }
  add(1, 'skills/get', { skill: entry() });
  add(2, 'resources/read', { contents: [{ uri, text }] });
  add(3, 'resources/read', { contents: [{ uri: 'skill://sample/asset.bin', blob: files['skill://sample/asset.bin'].toString('base64') }] }, 'skill://sample/asset.bin');
  return { capture: { schemaVersion: 1, specCommit: SKILLS_SPEC.commit, protocolVersion: '2026-07-28', origin: 'fixture-A', skillUri: uri,
    held: 1, reads: [2, 3], directories: [], listings: [], wire }, oracle: { origin: 'fixture-A', skillUri: uri, files }, add };
}
const result = (s, id) => s.capture.wire.find(w => w.direction === 'from-server' && w.message.id === id).message.result;
const verify = s => verifySkillCapture(s.capture, s.oracle);

test('all declared UTF-8/BOM/CRLF/multibyte and binary bytes bind to the independent oracle', () => {
  const s = sample(), report = verify(s);
  assertSkillVerification(report, 'consistent');
  assert.equal(report.coverage.declaredSetComplete, true);
  assert.equal(report.coverage.verifiedMembers, 2);
  assert.equal(report.coverage.unadvertisedFiles, 'unknown');
  assert.equal(report.reads[0].sha256, digest(files[uri]).slice(7));
  assert.equal(report.reads[1].encoding, 'base64');
});

for (const [name, mutate, status] of [
  ['same-size tamper', s => { result(s, 2).contents[0].text = text.replace('雪', '雨'); }, 'mismatch'],
  ['newline normalization', s => { result(s, 2).contents[0].text = text.replaceAll('\r\n', '\n'); }, 'mismatch'],
  ['size mismatch', s => { result(s, 1).skill.resources[0].size++; }, 'mismatch'],
  ['digest mismatch', s => { result(s, 1).skill.resources[0].digest = 'sha256:' + '0'.repeat(64); }, 'mismatch'],
  ['omitted last read', s => { s.capture.reads.pop(); }, 'incomplete'],
  ['wrong origin even identical bytes', s => { s.capture.origin = 'fixture-B'; }, 'mismatch'],
  ['wrong URI', s => { result(s, 2).contents[0].uri = 'skill://other/SKILL.md'; }, 'mismatch'],
  ['extra contents', s => { result(s, 2).contents.push(result(s, 2).contents[0]); }, 'invalid'],
  ['duplicate manifest entry', s => { result(s, 1).skill.resources.push(result(s, 1).skill.resources[0]); }, 'invalid'],
  ['absent self', s => { result(s, 1).skill.resources.shift(); }, 'invalid'],
  ['missing manifest', s => { delete result(s, 1).skill.resources; }, 'invalid'],
  ['dynamic manifest', s => { result(s, 1).skill.resources = 'dynamic'; }, 'incomplete'],
  ['invalid digest syntax', s => { result(s, 1).skill.resources[0].digest = 'sha256:AB'; }, 'invalid'],
  ['negative size', s => { result(s, 1).skill.resources[0].size = -1; }, 'invalid'],
  ['unsupported URI plus read outside advertised set', s => { result(s, 1).skill.resources[1].uri = 'skill://sample/%2e%2e/asset.bin'; }, 'mismatch'],
  ['sibling prefix escape', s => { result(s, 1).skill.resources[1].uri = 'skill://sample-other/asset.bin'; }, 'invalid'],
  ['noncanonical base64', s => { result(s, 3).contents[0].blob = 'AP8NCg'; }, 'invalid'],
  ['malformed Unicode', s => { result(s, 2).contents[0].text = '\ud800'; }, 'invalid'],
  ['frontmatter discrepancy', s => { result(s, 1).skill.frontmatter.description = 'Another description'; }, 'mismatch'],
  ['unknown capture contract', s => { s.capture.schemaVersion = 2; }, 'incomplete'],
  ['missing captured response', s => { s.capture.wire.splice(3, 1); }, 'incomplete'],
  ['duplicate response', s => { s.capture.wire.push(s.capture.wire[3]); }, 'invalid'],
  ['truncated retained wire', s => { s.capture.wire[3] = { direction: 'from-server', truncated: true }; }, 'incomplete'],
  ['RPC read error', s => { const w = s.capture.wire[3].message; delete w.result; w.error = { code: -32603, message: 'fixture unavailable' }; }, 'incomplete'],
]) test(name + ' never inherits a consistent aggregate', () => {
  const s = sample(); mutate(s);
  const report = verify(s);
  assertSkillVerification(report, status);
  assert.throws(() => assertSkillVerification(report, 'consistent'));
});

test('refresh retains old history but rechecks frontmatter even with unchanged resources', () => {
  const s = sample(), refreshed = entry(); refreshed.frontmatter.description = 'Different metadata';
  s.add(4, 'skills/get', { skill: refreshed }); s.capture.refresh = 4;
  const report = verify(s);
  assertSkillVerification(report, 'mismatch');
  assert.equal(report.reads.every(r => r.verified), true);
  assert.equal(report.coverage.declaredSetComplete, false);
});

test('order-only refresh can retain consistency; lost refresh cannot', () => {
  const s = sample(), refreshed = entry(); refreshed.resources.reverse();
  s.add(4, 'skills/get', { skill: refreshed }); s.capture.refresh = 4;
  assertSkillVerification(verify(s), 'consistent');
  s.capture.wire.pop(); assertSkillVerification(verify(s), 'incomplete');
});

test('changed, removed and dynamic refreshed sets never reuse old verification', () => {
  for (const change of ['changed', 'removed', 'dynamic']) {
    const s = sample(), refreshed = entry();
    if (change === 'changed') refreshed.resources[1].digest = 'sha256:' + '1'.repeat(64);
    if (change === 'removed') refreshed.resources.pop();
    if (change === 'dynamic') refreshed.resources = 'dynamic';
    s.add(4, 'skills/get', { skill: refreshed }); s.capture.refresh = 4;
    assert.notEqual(verify(s).status, 'consistent');
  }
});

test('partial catalog does not falsify a complete selected get or imply complete catalog', () => {
  const s = sample(); s.add(4, 'skills/list', { skills: [], nextCursor: 'next' }); s.capture.listings = [4];
  const report = verify(s); assertSkillVerification(report, 'consistent');
  assert.equal(report.coverage.catalogComplete, false);
});

test('directory-only added child and incomplete directory cannot inherit current aggregate', () => {
  for (const partial of [false, true]) {
    const s = sample(); s.add(4, 'resources/directory/read', { resources: partial ? [] : [{ uri: 'skill://sample/new.txt', name: 'new.txt' }], ...(partial ? { nextCursor: 'next' } : {}) }, 'skill://sample'); s.capture.directories = [4];
    assertSkillVerification(verify(s), partial ? 'incomplete' : 'changed');
  }
});

test('relabeling a nonclean verdict or fabricating a clean aggregate fails the gate', () => {
  const s = sample(); s.capture.reads.pop(); const report = verify(s);
  assert.throws(() => assertSkillVerification(report, 'consistent'));
  assert.throws(() => assertSkillVerification({ ...report, status: 'consistent' }, 'consistent'));
  assert.throws(() => assertSkillVerification({ status: 'consistent' }, 'consistent'));
});

test('later catalog entries cannot hide duplicate, dynamic or frontmatter transitions', () => {
  for (const mode of ['duplicate', 'dynamic', 'frontmatter']) {
    const s = sample(), next = entry();
    if (mode === 'dynamic') next.resources = 'dynamic';
    if (mode === 'frontmatter') next.frontmatter.description = 'New metadata';
    s.add(4, 'skills/list', { skills: mode === 'duplicate' ? [next, next] : [next] }); s.capture.listings = [4];
    assert.notEqual(verify(s).status, 'consistent');
  }
});

test('directory coverage is tied to the selected skill and exact requested subtree', () => {
  const s = sample(); s.add(4, 'resources/directory/read', { resources: [] }, 'skill://unrelated'); s.capture.directories = [4];
  assert.notEqual(verify(s).status, 'consistent');
  assert.equal(verify(s).coverage.directoryComplete, false);
});

test('causal windows reject response-before-request, reads-before-held and refresh-before-held', () => {
  for (const change of ['response', 'read', 'refresh']) {
    const s = sample();
    if (change === 'response') [s.capture.wire[2], s.capture.wire[3]] = [s.capture.wire[3], s.capture.wire[2]];
    if (change === 'read') s.capture.wire.unshift(...s.capture.wire.splice(2, 2));
    if (change === 'refresh') { s.add(4, 'skills/get', { skill: entry() }); s.capture.refresh = 4; s.capture.wire.unshift(...s.capture.wire.splice(6, 2)); }
    assert.notEqual(verify(s).status, 'consistent');
  }
  const s = sample(); [s.capture.wire[3], s.capture.wire[4]] = [s.capture.wire[4], s.capture.wire[3]];
  assertSkillVerification(verify(s), 'consistent'); // Concurrent read requests are valid.
});

test('missing and malformed wire is an explicit nonclean result, not a throw', () => {
  for (const wire of [undefined, null, [null], [1], []]) {
    const s = sample(); s.capture.wire = wire;
    assert.notEqual(verify(s).status, 'consistent');
  }
});

test('frontmatter name cannot identify a different URI path even when every byte agrees', () => {
  const s = sample(), changed = text.replace('name: sample', 'name: other'), bytes = Buffer.from(changed);
  result(s, 1).skill.frontmatter.name = 'other'; result(s, 1).skill.resources[0] = { uri, size: bytes.length, digest: digest(bytes) };
  result(s, 2).contents[0].text = changed; s.oracle.files = { ...files, [uri]: bytes };
  assertSkillVerification(verify(s), 'invalid');
});

test('valid concurrent response reordering keeps separate wire hashes and equal verification', () => {
  const a = sample(), b = sample();
  b.capture.wire = [b.capture.wire[0], b.capture.wire[1], b.capture.wire[2], b.capture.wire[4], b.capture.wire[5], b.capture.wire[3]];
  const direct = verify(a), guarded = verify(b);
  assert.notEqual(direct.bindings.wireSha256, guarded.bindings.wireSha256);
  assertSkillPair(direct, guarded, 'consistent');
  guarded.reads[0].sha256 = '0'.repeat(64);
  assert.throws(() => assertSkillPair(direct, guarded, 'consistent'));
});

test('modern cache/result fields and unsupported protocol stay incomplete', () => {
  for (const field of ['resultType', 'ttlMs', 'cacheScope']) {
    const s = sample(); delete result(s, 2)[field]; assertSkillVerification(verify(s), 'incomplete');
  }
  const s = sample(); s.capture.protocolVersion = '1900-01-01'; assertSkillVerification(verify(s), 'incomplete');
});

test('duplicate selected catalog entries across pages cannot become complete', () => {
  const s = sample(); s.add(4, 'skills/list', { skills: [entry()], nextCursor: 'next' });
  s.add(5, 'skills/list', { skills: [entry()] }, uri, { cursor: 'next' }); s.capture.listings = [4, 5];
  assertSkillVerification(verify(s), 'invalid');
});

test('resource profile limits are explicit gaps, not universal invalidity', () => {
  const s = sample(), resources = result(s, 1).skill.resources;
  for (let i = 2; i < 512; i++) resources.push({ uri: `skill://sample/file-${i}`, size: 0, digest: digest(Buffer.alloc(0)) });
  assert.ok(!verify(s).issues.some(i => i.code === 'held-resource-profile-limit'));
  resources.push({ uri: 'skill://sample/file-512', size: 0, digest: digest(Buffer.alloc(0)) });
  assert.ok(verify(s).issues.some(i => i.kind === 'incomplete' && i.code === 'held-resource-profile-limit'));
  const b = sample(); result(b, 1).skill.resources[1].size = 16 * 1024 * 1024 - files[uri].length;
  assert.ok(!verify(b).issues.some(i => i.code === 'held-byte-profile-limit'));
  result(b, 1).skill.resources[1].size++;
  assert.ok(verify(b).issues.some(i => i.kind === 'incomplete' && i.code === 'held-byte-profile-limit'));
});

test('held request cannot stand in for a missing refresh observation', () => {
  const s = sample(); s.capture.refresh = s.capture.held;
  assertSkillVerification(verify(s), 'invalid');
});

test('clean aggregate gate derives unique member coverage and byte bindings from actual rows', () => {
  for (const corrupt of [
    report => report.reads.pop(),
    report => { report.reads[1].uri = report.reads[0].uri; },
    report => { report.reads[1].requestId = report.reads[0].requestId; },
    report => { report.reads[1].size++; },
    report => { report.reads[1].sha256 = '0'.repeat(64); },
    report => { report.reads[1].oracleSha256 = '0'.repeat(64); },
    report => { report.held.resources.pop(); },
  ]) {
    const report = verify(sample()); corrupt(report);
    assert.throws(() => assertSkillVerification(report, 'consistent'));
  }
});

test('decodable unlisted content retains raw-byte evidence without verification credit', () => {
  const s = sample(), extra = Buffer.from('Unlisted 雪\r\n'), extraUri = 'skill://sample/extra.txt';
  s.add(4, 'resources/read', { contents: [{ uri: extraUri, text: extra.toString('utf8') }] }, extraUri);
  s.capture.reads.push(4); s.oracle.readFiles = { ...files, [extraUri]: extra };
  const report = verify(s); assertSkillVerification(report, 'mismatch');
  assert.equal(report.reads.at(-1).sha256, digest(extra).slice(7));
  assert.equal(report.reads.at(-1).size, extra.length);
  assert.equal(report.reads.at(-1).verified, false);
});

test('ambiguous directory children cannot establish scoped coverage', () => {
  for (const suffix of ['..', '%2e%2e', '']) {
    const s = sample(); s.add(4, 'resources/directory/read', { resources: [{ uri: 'skill://sample/' + suffix, name: suffix, mimeType: 'inode/directory' }] }, 'skill://sample'); s.capture.directories = [4];
    assert.notEqual(verify(s).status, 'consistent');
    assert.equal(verify(s).coverage.directoryComplete, false);
  }
});

test('lost capture roles cannot hide later selected traffic retained on the wire', () => {
  for (const kind of ['refresh', 'read', 'catalog', 'directory', 'orphan']) {
    const s = sample();
    if (kind === 'refresh') { const next = entry(); next.resources = 'dynamic'; s.add(4, 'skills/get', { skill: next }); }
    if (kind === 'read') s.add(4, 'resources/read', { contents: [{ uri: 'skill://sample/unlisted.txt', text: 'Unlisted' }] }, 'skill://sample/unlisted.txt');
    if (kind === 'catalog') s.add(4, 'skills/list', { skills: [{ ...entry(), resources: 'dynamic' }] });
    if (kind === 'directory') s.add(4, 'resources/directory/read', { resources: [{ uri: 'skill://sample/new.txt', name: 'new.txt' }] }, 'skill://sample');
    if (kind === 'orphan') { const next = entry(); next.resources = 'dynamic'; s.add(4, 'skills/get', { skill: next }); s.capture.wire.splice(-2, 1); }
    // The actual request/response remains; the harness lost its role metadata.
    assertSkillVerification(verify(s), 'incomplete');
  }
});

test('role IDs cannot overlap; unrelated skill traffic stays outside selected verification', () => {
  const s = sample(); s.add(4, 'skills/list', { skills: [entry()] }); s.capture.listings = [4]; s.capture.refresh = 4;
  assertSkillVerification(verify(s), 'invalid');
  const other = sample(); other.add(4, 'resources/read', { contents: [{ uri: 'skill://unrelated/file', text: 'Other skill' }] }, 'skill://unrelated/file');
  assertSkillVerification(verify(other), 'consistent');
});

test('trusted refreshed-state oracle requires fresh evidence even when the entire observation is lost', () => {
  const s = sample(); s.oracle.refreshedFiles = { ...files };
  assertSkillVerification(verify(s), 'incomplete');
});

test('cursor page requests must follow the prior page response on the actual wire', () => {
  const s = sample();
  s.add(4, 'resources/directory/read', { resources: [{ uri, name: 'SKILL.md' }], nextCursor: 'next' }, 'skill://sample');
  s.add(5, 'resources/directory/read', { resources: [{ uri: 'skill://sample/asset.bin', name: 'asset.bin' }] }, 'skill://sample', { cursor: 'next' });
  s.capture.directories = [4, 5];
  assertSkillVerification(verify(s), 'consistent');
  s.capture.wire.splice(6, 0, ...s.capture.wire.splice(8, 2));
  assertSkillVerification(verify(s), 'invalid');
});

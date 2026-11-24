import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { parseDocument } from 'yaml';

export const SKILLS_SPEC = Object.freeze({ commit: '649f7aee87d631ac4d1fdd3b12eef0c6264fdb3a',
  sha256: '6e33a33762783a02dc4c13c889dda5b8d7c525649012cf77da12d80c04ce6851' });
const ranks = { consistent: 0, incomplete: 1, changed: 2, mismatch: 3, invalid: 4 };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const jsonSha = value => sha(Buffer.from(JSON.stringify(value) ?? 'null'));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const statusOf = issues => issues.reduce((status, issue) => ranks[issue.kind] > ranks[status] ? issue.kind : status, 'consistent');

// This fixture profile does not resolve URI aliases, paths or network locations.
function supportedUri(uri) {
  return typeof uri === 'string' && /^[a-z][a-z0-9+.-]*:\/\/[^\s%?#\\]+$/i.test(uri)
    && !uri.split('/').some(part => part === '.' || part === '..');
}
function frontmatter(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const match = /^\uFEFF?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(text);
  assert.ok(match, 'missing frontmatter');
  const document = parseDocument(match[1], { uniqueKeys: true });
  assert.equal(document.errors.length, 0, 'malformed frontmatter');
  const value = document.toJS({ maxAliasCount: 0 });
  assert.ok(object(value), 'frontmatter is not a mapping');
  return value;
}

export function verifySkillCapture(capture, oracle) {
  const issues = [], reads = [];
  const issue = (kind, code) => { if (!issues.some(i => i.kind === kind && i.code === code)) issues.push({ kind, code }); };
  const coverage = { declaredMembers: 0, verifiedMembers: 0, declaredSetComplete: false,
    catalogComplete: null, directoryComplete: null, directoryUri: null, unadvertisedFiles: 'unknown' };
  const report = { schemaVersion: 1, spec: SKILLS_SPEC, identity: { origin: capture.origin, uri: capture.skillUri },
    status: 'incomplete', issues, reads, coverage, held: null, refresh: null, transitions: [],
    bindings: { wireSha256: jsonSha(capture.wire), oracleSha256: jsonSha(Object.entries(oracle.files).map(([uri, bytes]) => [uri, bytes.length, sha(bytes)])) } };
  if (capture.schemaVersion !== 1 || capture.specCommit !== SKILLS_SPEC.commit) issue('incomplete', 'unsupported-capture-contract');
  if (!['2026-07-28', '2025-11-25'].includes(capture.protocolVersion)) issue('incomplete', 'unsupported-capture-protocol');
  if (capture.origin !== oracle.origin || capture.skillUri !== oracle.skillUri) issue('mismatch', 'origin-or-skill-identity');
  if (capture.refresh !== undefined && capture.refresh === capture.held) issue('invalid', 'refresh-aliases-held-request');
  if (oracle.refreshedFiles !== undefined && capture.refresh === undefined) issue('incomplete', 'required-refresh-evidence-missing');
  if (!supportedUri(capture.skillUri) || !capture.skillUri.endsWith('/SKILL.md')) issue('incomplete', 'unsupported-skill-uri');
  const wire = Array.isArray(capture.wire) ? capture.wire : [];
  if (!Array.isArray(capture.wire) || wire.length > 256 || wire.some(w => !object(w) || w.truncated)
    || Buffer.byteLength(JSON.stringify(wire)) > 16 * 1024 * 1024) issue('incomplete', 'capture-budget-or-truncation');
  const ids = value => {
    if (value === undefined) return [];
    if (!Array.isArray(value)) { issue('invalid', 'invalid-capture-role-array'); return []; }
    return value;
  };
  const readIds = ids(capture.reads), directoryIds = ids(capture.directories), listingIds = ids(capture.listings);
  const assigned = [capture.held, ...readIds, ...directoryIds, ...listingIds, ...(capture.refresh === undefined ? [] : [capture.refresh])];
  if (new Set(assigned).size !== assigned.length) issue('invalid', 'overlapping-capture-roles');
  const entryIds = new Set([capture.held, capture.refresh, ...listingIds]);
  const root = typeof capture.skillUri === 'string' ? capture.skillUri.slice(0, -'/SKILL.md'.length) : null;
  const selectedUri = uri => typeof uri === 'string' && root !== null && (uri === root || uri.startsWith(root + '/'));
  for (const event of wire) {
    if (!object(event?.message)) continue;
    const message = event.message;
    if (event.direction === 'to-server') {
      const missing = (message.method === 'skills/get' && message.params?.uri === capture.skillUri && !entryIds.has(message.id))
        || (message.method === 'skills/list' && !entryIds.has(message.id))
        || (message.method === 'resources/read' && selectedUri(message.params?.uri) && !readIds.includes(message.id))
        || (message.method === 'resources/directory/read' && selectedUri(message.params?.uri) && !directoryIds.includes(message.id));
      if (missing) issue('incomplete', 'selected-traffic-without-capture-role');
    } else if (event.direction === 'from-server' && !('method' in message)) {
      const requests = wire.filter(w => w?.direction === 'to-server' && object(w.message) && 'method' in w.message && w.message.id === message.id);
      if (requests.length !== 1) issue(requests.length ? 'invalid' : 'incomplete', 'unattributed-response');
    }
  }

  function response(id, methods) {
    if (!Number.isSafeInteger(id) || id < 1) { issue('incomplete', 'missing-request-id'); return null; }
    const requests = wire.filter(w => w?.direction === 'to-server' && object(w.message) && w.message.id === id);
    const responses = wire.filter(w => w?.direction === 'from-server' && object(w.message) && w.message.id === id && !('method' in w.message));
    if (requests.length !== 1 || responses.length !== 1) {
      issue(requests.length > 1 || responses.length > 1 ? 'invalid' : 'incomplete', 'request-response-correlation'); return null;
    }
    const request = requests[0].message, message = responses[0].message;
    const requestIndex = wire.indexOf(requests[0]), responseIndex = wire.indexOf(responses[0]);
    if (!methods.includes(request.method) || responseIndex <= requestIndex) { issue('invalid', 'request-response-causality'); return null; }
    if (request.jsonrpc !== '2.0' || message.jsonrpc !== '2.0' || ('result' in message) === ('error' in message)) {
      issue('invalid', 'invalid-jsonrpc-envelope'); return null;
    }
    if ('error' in message) { issue('incomplete', 'rpc-error'); return null; }
    if (!object(message.result) || (message.result.resultType !== undefined && message.result.resultType !== 'complete')) {
      issue('incomplete', 'incomplete-result'); return null;
    }
    if (capture.protocolVersion === '2026-07-28' && (message.result.resultType !== 'complete'
      || !Number.isSafeInteger(message.result.ttlMs) || message.result.ttlMs < 0 || !['private', 'public'].includes(message.result.cacheScope))) {
      issue('incomplete', 'missing-modern-result-contract'); return null;
    }
    return { request, result: message.result, requestIndex, responseIndex };
  }

  let heldResponseIndex = -1, lastReadResponseIndex = -1;
  function entry(id) {
    const observation = response(id, ['skills/get', 'skills/list']);
    if (!observation) return null;
    if (id === capture.held) heldResponseIndex = observation.responseIndex;
    else if (observation.requestIndex <= Math.max(heldResponseIndex, lastReadResponseIndex)) issue('invalid', 'refresh-before-held-read-window');
    const { request, result } = observation;
    if (request.method === 'skills/get') {
      if (request.params?.uri !== capture.skillUri) issue('mismatch', 'entry-request-uri');
      return result.skill;
    }
    if (!Array.isArray(result.skills)) { issue('invalid', 'invalid-skill-list'); return null; }
    const selected = result.skills.filter(s => s?.uri === capture.skillUri);
    if (selected.length !== 1) { issue(selected.length ? 'invalid' : 'incomplete', 'selected-entry-not-unique-or-absent'); return null; }
    return selected[0];
  }
  function manifest(value, expectedFiles, label) {
    if (value === null) return null;
    if (!object(value) || value.uri !== capture.skillUri || !object(value.frontmatter)
      || typeof value.frontmatter.name !== 'string' || typeof value.frontmatter.description !== 'string') {
      issue('invalid', `${label}-invalid-entry`); return null;
    }
    if (value.frontmatter.name !== capture.skillUri.slice(0, -'/SKILL.md'.length).split('/').at(-1)) issue('invalid', `${label}-name-uri-mismatch`);
    if (value.resources === 'dynamic') { issue('incomplete', `${label}-dynamic`); return null; }
    if (!Array.isArray(value.resources)) { issue('invalid', `${label}-invalid-manifest`); return null; }
    if (value.resources.length > 512) { issue('incomplete', `${label}-resource-profile-limit`); return null; }
    const resources = new Map(), root = capture.skillUri.slice(0, -'SKILL.md'.length);
    let total = 0;
    for (const resource of value.resources) {
      if (!object(resource) || typeof resource.uri !== 'string' || typeof resource.digest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(resource.digest)
        || !Number.isSafeInteger(resource.size) || resource.size < 0) { issue('invalid', `${label}-invalid-resource`); continue; }
      if (!supportedUri(resource.uri)) { issue('incomplete', `${label}-unsupported-resource-uri`); continue; }
      if (!resource.uri.startsWith(root) || resource.uri.endsWith('/')) { issue('invalid', `${label}-outside-skill-resource`); continue; }
      if (resources.has(resource.uri)) { issue('invalid', `${label}-duplicate-resource`); continue; }
      resources.set(resource.uri, resource); total += resource.size;
      if (expectedFiles) {
        const expected = expectedFiles[resource.uri];
        if (!expected || resource.size !== expected.length || resource.digest !== 'sha256:' + sha(expected)) issue('mismatch', `${label}-independent-file-oracle`);
      }
    }
    if (!resources.has(capture.skillUri)) issue('invalid', `${label}-missing-self-resource`);
    if (!Number.isSafeInteger(total) || total > 16 * 1024 * 1024) issue('incomplete', `${label}-byte-profile-limit`);
    if (expectedFiles && Object.keys(expectedFiles).some(uri => !resources.has(uri))) issue('incomplete', `${label}-oracle-member-not-declared`);
    return resources;
  }
  const heldEntry = entry(capture.held), held = manifest(heldEntry, oracle.files, 'held');
  if (held) {
    coverage.declaredMembers = held.size;
    report.held = { requestId: capture.held, entrySha256: jsonSha(heldEntry), resources: [...held.values()] };
  }
  const verified = new Set(), bodies = new Map(), seenRequests = new Set();
  for (const id of readIds) {
    if (seenRequests.has(id)) { issue('invalid', 'duplicate-read-observation'); continue; }
    seenRequests.add(id);
    const observation = response(id, ['resources/read']);
    if (!observation) continue;
    if (observation.requestIndex <= heldResponseIndex) issue('invalid', 'read-before-held');
    lastReadResponseIndex = Math.max(lastReadResponseIndex, observation.responseIndex);
    const uri = observation.request.params?.uri, contents = observation.result.contents;
    const row = { requestId: id, origin: capture.origin, uri, verified: false }; reads.push(row);
    if (!Array.isArray(contents) || contents.length !== 1 || !object(contents[0])) { issue('invalid', 'ambiguous-resource-contents'); continue; }
    const content = contents[0];
    if (uri !== content.uri) { issue('mismatch', 'read-response-uri'); continue; }
    const resource = held?.get(uri);
    if (held && !resource) issue('mismatch', 'read-not-in-held-set');
    let bytes;
    if (typeof content.text === 'string' && !('blob' in content) && content.text.isWellFormed()) {
      bytes = Buffer.from(content.text, 'utf8'); row.encoding = 'utf8';
    } else if (typeof content.blob === 'string' && !('text' in content)
      && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(content.blob)) {
      bytes = Buffer.from(content.blob, 'base64'); row.encoding = 'base64';
      if (bytes.toString('base64') !== content.blob) { issue('invalid', 'noncanonical-base64'); continue; }
    } else { issue('invalid', 'invalid-resource-encoding'); continue; }
    row.size = bytes.length; row.sha256 = sha(bytes); bodies.set(uri, bytes);
    const expected = (oracle.readFiles ?? oracle.files)[uri];
    row.oracleSha256 = expected ? sha(expected) : null;
    if (!expected || !bytes.equals(expected)) issue('mismatch', 'read-independent-file-oracle');
    if (!resource) { if (!held) issue('incomplete', 'read-without-static-held-entry'); continue; }
    if (bytes.length !== resource.size || 'sha256:' + row.sha256 !== resource.digest) { issue('mismatch', 'read-size-or-digest'); continue; }
    if (uri === capture.skillUri) {
      try { if (!isDeepStrictEqual(frontmatter(bytes), heldEntry.frontmatter)) { issue('mismatch', 'held-frontmatter'); continue; } }
      catch { issue('invalid', 'invalid-frontmatter'); continue; }
    }
    row.verified = !!expected && bytes.equals(expected); if (row.verified) verified.add(uri);
  }
  coverage.verifiedMembers = verified.size;
  if (held && [...held.keys()].some(uri => !verified.has(uri))) issue('incomplete', 'held-members-unverified');
  function refreshedEntry(value, id, method) {
    const refreshed = manifest(value, oracle.refreshedFiles, 'refresh');
    if (refreshed) {
      const transition = { requestId: id, method, entrySha256: jsonSha(value), resources: [...refreshed.values()] };
      report.transitions.push(transition);
      if (id === capture.refresh) report.refresh = transition;
      const set = m => [...m.values()].map(r => [r.uri, r.digest, r.size]).sort((a, b) => a[0].localeCompare(b[0]));
      if (!held || !isDeepStrictEqual(set(held), set(refreshed))) issue('changed', 'refreshed-resource-set');
      const bytes = bodies.get(capture.skillUri);
      if (bytes && refreshed.get(capture.skillUri)?.digest === 'sha256:' + sha(bytes)) {
        try { if (!isDeepStrictEqual(frontmatter(bytes), value.frontmatter)) issue('mismatch', 'refreshed-frontmatter'); }
        catch { issue('invalid', 'invalid-refreshed-frontmatter'); }
      } else if (!isDeepStrictEqual(heldEntry?.frontmatter, value.frontmatter)) issue('changed', 'refreshed-frontmatter-unverified');
    }
  }
  if (capture.refresh !== undefined && capture.refresh !== capture.held) refreshedEntry(entry(capture.refresh), capture.refresh, 'skills/get');
  function pages(ids, method, field, directory) {
    if (!ids?.length) return null;
    let expectedCursor, complete = true, seenSelected = false, previousResponseIndex = -1;
    const seenChildren = new Set();
    const cursors = new Set();
    for (const id of ids) {
      const observation = response(id, [method]);
      if (!observation) { complete = false; continue; }
      const { request, result } = observation;
      if (observation.requestIndex <= heldResponseIndex) issue('invalid', 'page-before-held');
      if (observation.requestIndex <= previousResponseIndex) { issue('invalid', 'page-causality'); complete = false; }
      previousResponseIndex = observation.responseIndex;
      if (request.params?.cursor !== expectedCursor || cursors.has(request.params?.cursor)) { issue('invalid', 'page-correlation'); complete = false; }
      cursors.add(request.params?.cursor);
      if (!Array.isArray(result[field])) { issue('invalid', 'invalid-page'); complete = false; continue; }
      if (!directory) {
        const selected = result.skills.filter(skill => skill?.uri === capture.skillUri);
        if (selected.length > 1 || (selected.length === 1 && seenSelected)) { issue('invalid', 'duplicate-catalog-entry'); complete = false; }
        else if (selected.length === 1) { seenSelected = true; refreshedEntry(selected[0], id, method); }
      }
      if (directory) {
        const uri = request.params?.uri, root = capture.skillUri.slice(0, -'/SKILL.md'.length);
        if (!supportedUri(uri) || (uri !== root && !uri.startsWith(root + '/'))) {
          issue('mismatch', 'directory-outside-selected-skill'); complete = false; continue;
        }
        if (coverage.directoryUri !== null && coverage.directoryUri !== uri) { issue('invalid', 'directory-page-uri-change'); complete = false; continue; }
        coverage.directoryUri = uri;
        for (const resource of result[field]) {
          if (!supportedUri(resource?.uri)) { issue('incomplete', 'unsupported-directory-child-uri'); complete = false; continue; }
          if (!resource.uri.startsWith(uri + '/') || !resource.uri.slice(uri.length + 1) || resource.uri.slice(uri.length + 1).includes('/')) {
            issue('invalid', 'directory-not-direct-child'); complete = false;
          }
          if (seenChildren.has(resource?.uri)) { issue('invalid', 'duplicate-directory-child'); complete = false; }
          seenChildren.add(resource?.uri);
        }
      }
      if (directory && held) for (const resource of result[field]) {
        if (resource?.mimeType !== 'inode/directory' && !held.has(resource?.uri)) issue('changed', 'directory-child-not-in-held-set');
      }
      expectedCursor = result.nextCursor;
    }
    if (expectedCursor !== undefined) complete = false;
    if (directory && !complete) issue('incomplete', 'directory-pages-incomplete');
    return complete;
  }
  coverage.catalogComplete = pages(listingIds, 'skills/list', 'skills', false);
  coverage.directoryComplete = pages(directoryIds, 'resources/directory/read', 'resources', true);
  report.status = statusOf(issues);
  coverage.declaredSetComplete = report.status === 'consistent' && held !== null && verified.size === held.size;
  return report;
}

export function assertSkillVerification(report, expectedStatus) {
  assert.equal(report.schemaVersion, 1, 'missing retained verification contract');
  assert.ok(Array.isArray(report.issues) && report.issues.every(issue => Object.hasOwn(ranks, issue.kind) && issue.kind !== 'consistent'), 'unknown verification issue');
  assert.equal(report.status, expectedStatus, 'retained verification outcome differs');
  assert.equal(report.status, statusOf(report.issues), 'relabelled retained verification');
  if (expectedStatus === 'consistent') {
    assert.equal(report.coverage.declaredSetComplete, true, 'unverified members cannot be clean');
    assert.notEqual(report.coverage.directoryComplete, false, 'directory scope remains incomplete');
    const members = new Map(report.held.resources.map(resource => [resource.uri, resource]));
    assert.ok(members.has(report.identity.uri) && members.size > 0);
    assert.equal(members.size, report.held.resources.length, 'duplicate held members');
    const verifiedUris = new Set(), requestIds = new Set();
    assert.ok(report.reads.length > 0 && report.reads.every(read => read.verified), 'missing verified resource reads');
    for (const read of report.reads) {
      const member = members.get(read.uri);
      assert.ok(member, 'verified read is absent from the held manifest');
      assert.equal(read.origin, report.identity.origin);
      assert.match(read.sha256, /^[a-f0-9]{64}$/);
      assert.equal(member.digest, 'sha256:' + read.sha256); assert.equal(read.oracleSha256, read.sha256);
      assert.ok(Number.isSafeInteger(read.size) && read.size >= 0); assert.equal(read.size, member.size);
      assert.ok(Number.isSafeInteger(read.requestId) && !requestIds.has(read.requestId), 'duplicate read request');
      requestIds.add(read.requestId); verifiedUris.add(read.uri);
    }
    assert.equal(verifiedUris.size, members.size, 'a held member lacks a verified read');
    assert.equal(report.coverage.declaredMembers, members.size);
    assert.equal(report.coverage.verifiedMembers, verifiedUris.size);
  } else assert.equal(report.coverage.declaredSetComplete, false);
}

export function assertSkillPair(direct, guarded, expectedStatus) {
  assertSkillVerification(direct, expectedStatus); assertSkillVerification(guarded, expectedStatus);
  const { bindings: a, ...directSemantics } = direct, { bindings: b, ...guardedSemantics } = guarded;
  assert.deepEqual(guardedSemantics, directSemantics, 'guard changed retained verification semantics');
  assert.equal(b.oracleSha256, a.oracleSha256, 'fixture oracle changed between connections');
  for (const bindings of [a, b]) assert.match(bindings.wireSha256, /^[a-f0-9]{64}$/);
}

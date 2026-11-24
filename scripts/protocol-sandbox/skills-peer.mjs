import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

export async function serveRetainedSkills(cli, scenarioId, observe) {
  const require = createRequire(cli);
  const { McpServer } = await import(require.resolve('@modelcontextprotocol/server'));
  const { SkillsExtension, skillEntry } = await import(require.resolve('@modelcontextprotocol/server/ext/skills'));
  const { serveStdio, StdioServerTransport } = await import(require.resolve('@modelcontextprotocol/server/stdio'));
  const fixture = JSON.parse(await readFile(new URL('./skills-oracle.json', import.meta.url), 'utf8'));
  const scenario = fixture.cases.find(c => c.id === scenarioId);
  if (!scenario) throw Error('unknown retained Skills fixture');
  async function state(name) {
    return Object.fromEntries(await Promise.all(Object.entries(fixture.states[name]).map(async ([path, file]) =>
      [path, await readFile(new URL(file, import.meta.url))])));
  }
  const initial = await state(scenario.initial ?? 'baseline');
  const reading = await state(scenario.read ?? scenario.initial ?? 'baseline');
  const refreshed = await state(scenario.refresh ?? scenario.initial ?? 'baseline');
  const directory = await state(scenario.directory ?? scenario.initial ?? 'baseline');
  const root = fixture.skillUri.slice(0, -'SKILL.md'.length);
  const metadata = await skillEntry('mcpm', { 'SKILL.md': await readFile(new URL('./mcpm-SKILL.md', import.meta.url)) });
  function entry(files, mode) {
    const value = { ...metadata, frontmatter: structuredClone(metadata.frontmatter), resources: Object.entries(files).map(([path, bytes]) => ({
      uri: root + path, digest: 'sha256:' + createHash('sha256').update(bytes).digest('hex'), size: bytes.length,
    })) };
    if (mode === 'dynamic') value.resources = 'dynamic';
    if (mode === 'absent') delete value.resources;
    if (mode === 'self-absent') value.resources = value.resources.filter(r => r.uri !== fixture.skillUri);
    if (mode === 'duplicate') value.resources.push(value.resources[0]);
    if (mode === 'digest') value.resources[1].digest = 'sha256:' + '0'.repeat(64);
    if (mode === 'size') value.resources[1].size++;
    if (mode === 'frontmatter') value.frontmatter.description = 'A changed advertised description';
    if (mode === 'reorder') value.resources.reverse();
    return value;
  }
  let gets = 0;
  const source = {
    list: async ({ cursor }) => scenario.catalogPages === 'partial'
      ? { skills: [], nextCursor: 'remaining' }
      : cursor ? { skills: [] } : { skills: [entry(initial, scenario.heldMode)], nextCursor: 'remaining' },
    get: async uri => uri !== fixture.skillUri ? undefined : ++gets === 1
      ? entry(initial, scenario.heldMode) : entry(refreshed, scenario.refreshMode),
    read: async uri => {
      const path = uri.slice(root.length), bytes = reading[path];
      if (!uri.startsWith(root) || !bytes || path === scenario.missingRead) return undefined;
      return path.endsWith('.bin') ? { bytes, mimeType: 'application/octet-stream' } : { text: bytes.toString('utf8'), mimeType: 'text/markdown' };
    },
    readDirectory: async (uri, { cursor }) => {
      if (!uri.startsWith(root) || !scenario.directory) return undefined;
      const prefix = uri.slice(root.length) + '/';
      const children = new Map();
      for (const path of Object.keys(directory)) if (path.startsWith(prefix)) {
        const rest = path.slice(prefix.length), name = rest.split('/')[0];
        children.set(name, { uri: uri + '/' + name, name, ...(rest.includes('/') ? { mimeType: 'inode/directory' } : {}) });
      }
      const resources = [...children.values()];
      if (scenario.directoryPages) return cursor ? { resources: resources.slice(1) } : { resources: resources.slice(0, 1), nextCursor: 'remaining' };
      return { resources };
    },
  };
  const server = new McpServer({ name: 'sandbox', version: '1' });
  new SkillsExtension({ source }).attach(server);
  await serveStdio(() => server, { transport: observe(new StdioServerTransport()), legacy: 'serve' });
}

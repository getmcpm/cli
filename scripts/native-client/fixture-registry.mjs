import { createHash } from 'node:crypto';

export const serverName = 'io.github.getmcpm/native-fixture';
export const packageName = '@mcpm/native-fixture';
export function fixtureMetadata(url, latest = '1.0.0') {
  const u = new URL(url);
  if (u.origin === 'https://registry.modelcontextprotocol.io') {
    const match = decodeURIComponent(u.pathname).match(/^\/v0\.1\/servers\/io\.github\.getmcpm\/native-fixture\/versions\/(latest|1\.0\.0|2\.0\.0)$/);
    if (!match) throw new Error(`Unexpected registry request: ${u.pathname}`);
    const version = match[1] === 'latest' ? latest : match[1];
    return { server: { name: serverName, description: 'Synthetic native-client compatibility fixture.', version,
      repository: { source: 'github', url: 'https://github.com/getmcpm/cli' },
      packages: [{ registryType: 'npm', identifier: packageName, version, transport: { type: 'stdio' } }],
    }, _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', publishedAt: '2026-01-01T00:00:00Z', isLatest: version === latest } } };
  }
  if (u.origin === 'https://registry.npmjs.org' && decodeURIComponent(u.pathname).startsWith('/' + packageName)) {
    const version = decodeURIComponent(u.pathname).split('/').at(-1);
    if (!['1.0.0', '2.0.0'].includes(version)) throw new Error('Unexpected fixture package version');
    return { name: packageName, version, dist: { integrity: 'sha512-' + createHash('sha512').update(`synthetic-${version}`).digest('base64') } };
  }
  throw new Error(`Network forbidden in fixture CLI: ${u.origin}${u.pathname}`);
}

// Only the explicitly marked fixture CLI gets synthetic registry responses.
// Native clients, the guard and peer run without this loader.
if (process.env.MCPM_NATIVE_REGISTRY_DOUBLE === '1') {
  globalThis.fetch = async input => new Response(JSON.stringify(fixtureMetadata(String(input), process.env.MCPM_NATIVE_VERSION)), {
    status: 200, headers: { 'content-type': 'application/json' },
  });
}

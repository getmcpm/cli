# mcpm homepage

A standalone static site. A small staging script copies the public asset
allowlist; there are no third-party scripts, fonts, analytics, or runtime dependencies. CLI source, packaging and public usage skill are unchanged.

Preview from the repository root:

```sh
python3 -m http.server 8080 --directory website --bind 127.0.0.1
```

Open http://127.0.0.1:8080. Serve over HTTPS when hosted; the optional copy button
requires the Clipboard API in a secure context. Commands remain selectable and
all navigation and disclosures work without JavaScript.

Publish only the staged `website/dist/` directory. The chosen address is
`https://mcpm.m1ngshum.com/`, also used as the canonical URL. Hosting, DNS and
publication are managed in the dedicated Netlify project below.

The logo is copied from `assets/logo-64.svg` in the repository. Command and
security copy comes from README.md and docs/{USAGE,GUARD,TRUST,PROJECT-SCOPE}.md;
keep it aligned when those contracts change. No sample command output is presented
as an actual scan result.

## Visual direction

Redesigned with UI UX Pro Max (upstream source commit
`9b675f0b13c9c28dec445e8ce4633c18c39b6467`): dark developer-tool surfaces,
semantic color tokens, code-focused previews, visible keyboard focus and responsive
layouts. The generated FAQ/support landing pattern was unsuitable for installation
and was not applied. System sans/monospace fonts avoid external font requests.
The six names identify supported configuration adapters, not endorsements or
universal native-client enforcement. Command previews contain no invented results.

## Production deployment

- Public URL: https://mcpm.m1ngshum.com/
- First published deploy: `6af2fe455c35c5307d7a2854` (2026-11-10).
- Acceptance: six public asset SHA-256 hashes matched the uploaded source; valid
  HTTPS, HTTP 301 redirect, seven responsive widths, clipboard states and
  no-JavaScript disclosures verified on the custom domain.
- Netlify team/project: `wwwdycg` / `mcpm-homepage`
- Site ID: `c627d7aa-2df6-4c5c-aeef-51c2501f117f`
- Dashboard: https://app.netlify.com/projects/mcpm-homepage
- Cloudflare DNS: DNS-only CNAME `mcpm` to `mcpm-homepage.netlify.app`.
- Public visitor access; preserve managed HTTPS and HTTP-to-HTTPS redirects.
- GitHub target: `getmcpm/cli`, production branch `main`. The repository connection
  must be completed in Netlify before Git deployments are active.
- Root `netlify.toml` sets base `website`, command `sh build.sh`, and publish `dist`
  (relative to the base directory). PR deploys are previews; merging to `main`
  publishes production once connected. Do not create a replacement project.

Publish only `index.html`, `styles.css`, `tokens.css`, `base.css`, `site.js`, and
`assets/logo.svg`, preserving their paths. Stage these six files into an empty
directory with `sh website/build.sh` and deploy `website/dist/` to the existing site. Never upload
the repository root, this README, local metadata, or credentials. The first
production upload on 2026-11-10 used Netlify's ZIP deployment API.

After each authorized deploy, confirm the published deploy is ready, compare all
six public files with the staged source, verify HTTPS and HTTP redirects, and
check desktop/mobile rendering, disclosures and the copy-command control.
Preserve the apex/personal homepage, private subdomains and all mail DNS records.

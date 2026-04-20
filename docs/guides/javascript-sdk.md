# JavaScript SDK & npm Wrapper

Use the `redblue-cli` package when you want to call redblue from Node.js or expose `rb` through npm tooling.

The package is a wrapper around the real redblue binary. It downloads the binary during `postinstall` to `node_modules/redblue-cli/.redblue/bin` when the package is installed.

## Requirements

- Node.js 20+
- A redblue binary available through one of these paths:
  - explicit `binaryPath`
  - npm package local install in `./node_modules/redblue-cli/.redblue/bin` (postinstall default)
  - managed install in `~/.local/bin/rb`
  - already installed in `PATH`
  - downloaded on demand with `autoDownload: true`

## Install

```bash
# Local install (project dependency)
npm install redblue-cli

# Optional global install
npm i -g redblue-cli
```

## CLI Usage

### Zero-install

```bash
npx redblue-cli dns record lookup example.com --type MX
npm exec --package redblue-cli rb -- tls security audit github.com
```

### After local install

```bash
npm install redblue-cli
npx rb network ports scan 192.168.1.1 --preset common
./node_modules/.bin/rb dns record lookup example.com --type A
```

Use global install:

```bash
rb dns record lookup example.com --type A
```

> **Note:** `npx rb` works when the package is already installed in the current project or globally. For one-shot remote execution, use `npx redblue-cli` or `npm exec --package redblue-cli rb -- ...`.

## Programmatic SDK

```js
const { createClient } = require('redblue-cli');

(async () => {
  const rb = await createClient();

  const ports = await rb.network.ports.scan({
    target: '192.168.1.1',
    preset: 'common'
  });

  const records = await rb.dns.record.lookup({
    target: 'example.com',
    type: 'MX'
  });

  console.log({ ports, records });
})();
```

### TypeScript

```ts
import { createClient, RedblueClient } from 'redblue-cli';

async function audit(rb: RedblueClient) {
  const records = await rb.dns.record.lookup({ target: 'example.com', type: 'MX' });
  const ports = await rb.network.ports.scan({ target: 'example.com', preset: 'common' });
  return { records, ports };
}

(async () => {
  const rb = await createClient();
  console.log(await audit(rb));
})();
```

The package ships with bundled TypeScript declarations at `sdk/index.d.ts`, so editor autocomplete and typed route signatures are available after `npm install redblue-cli`.

## Route Surface (dot notation)

Every CLI route is exposed as `client.<domain>.<resource>.<verb>(payload)`. The full catalog is generated from the binary manifest, so the SDK is always in sync with the installed `rb`.

Common paths:

| Path | Purpose |
|------|---------|
| `rb.dns.record.lookup` | Live DNS lookup (A, MX, TXT, …) |
| `rb.recon.domain.whois` | WHOIS / RDAP |
| `rb.recon.domain.subdomains` | Subdomain enumeration |
| `rb.recon.domain.describe` | Consolidated recon bundle (WHOIS + DNS + subs + TLS + HTTP) |
| `rb.web.asset.get` | HTTP fetch with full timing |
| `rb.web.asset.headers` | Response headers + security evaluation |
| `rb.web.asset.security` | Security grade |
| `rb.web.asset.describe` | Consolidated web asset bundle (headers + security + tech + TLS + HAR) |
| `rb.tls.security.audit` | TLS audit with JA3/JA3S |
| `rb.network.ports.scan` | Port scanner with presets |
| `rb.network.host.fingerprint` | Host OS/service fingerprint |
| `rb.intel.vuln.search` | CVE / KEV search |
| `rb.intel.vuln.cve` | CVE detail lookup |

### Three invocation modes

Each route function exposes three call modes:

```js
// 1. JSON (default) — executes and returns parsed JSON
const data = await rb.dns.record.lookup({ target: 'example.com' });

// 2. Raw — returns { code, stdout, stderr, args } with the text output intact
const raw = await rb.dns.record.lookup.raw({ target: 'example.com' });

// 3. Spawn — returns a Node ChildProcess for manual streaming
const child = rb.dns.record.lookup.spawn({ target: 'example.com' });
child.stdout.on('data', (chunk) => process.stdout.write(chunk));
```

### Route metadata

```js
console.log(rb.dns.record.lookup.meta);
// { command: <ManifestCommand>, route: <ManifestRoute> }
```

## Introspection

The client exposes a typed introspection surface. Prefer this over building raw `string[]` argv.

```js
const rb = await createClient();

// Every route with summary + flags + positionals
rb.$commands.forEach((entry) => console.log(entry.canonical_path, entry.summary));

// Inspect a single route
const descriptor = rb.$describe(['recon', 'domain', 'subdomains']);

// Render the same help text the CLI prints
console.log(rb.$help('recon/domain/subdomains'));

// Suggest completions for a partially typed selector
const { stage, completions } = rb.$complete(['recon', 'domain']);

// Find the invocation function for a canonical path
const lookup = rb.$findRoute('dns/record/lookup');
await lookup({ target: 'example.com', type: 'A' });

// Low-level access
console.log(rb.$binaryPath);
console.log(rb.$manifest.version);
```

## Typed Errors

`createClient` routes, `runJson`, and `ensureInstalled` throw typed errors so callers can branch on failure category instead of parsing messages.

```js
const {
  RedblueError,
  RedblueBinaryNotFoundError,
  RedblueRouteError,
  RedblueParseError,
  RedblueTimeoutError,
  RedblueChecksumError,
  RedblueNetworkError
} = require('redblue-cli');

try {
  await rb.recon.domain.subdomains({ target, timeout: 30_000 });
} catch (err) {
  if (err instanceof RedblueTimeoutError) scheduleRetry(err.timeout);
  else if (err instanceof RedblueBinaryNotFoundError) disableFeature(err);
  else if (err instanceof RedblueRouteError) reportSchemaDrift(err.route);
  else if (err instanceof RedblueParseError) logStderr(err.stderr, err.args);
  else throw err;
}
```

All errors extend `RedblueError` and expose a stable `err.code` (`REDBLUE_TIMEOUT`, `REDBLUE_ROUTE_ERROR`, `REDBLUE_PARSE_ERROR`, `REDBLUE_BINARY_NOT_FOUND`, `REDBLUE_CHECKSUM_MISMATCH`, `REDBLUE_NETWORK_ERROR`). Additional fields vary per subclass: `binaryPath`, `route`, `selector`, `stdout`, `stderr`, `args`, `timeout`, `expected`, `actual`, `statusCode`, `url`.

## Describe Bundles

Instead of orchestrating seven calls, use the consolidated bundles:

```js
const domain = await rb.recon.domain.describe({ target: 'example.com' });
// → { whois, dns, subdomains, tls, http, fingerprint, timings }

const asset = await rb.web.asset.describe({ target: 'https://example.com' });
// → { headers, security, technologies, tls, har }
```

## Binary Resolution

Resolution order (first match wins):

1. explicit `binaryPath`
2. package-local `<package>/.redblue/bin/rb` (postinstall default)
3. managed install at `~/.local/bin/rb` (or `REDBLUE_INSTALL_DIR`)
4. legacy `~/.redblue/bin/rb`
5. `PATH`
6. release download when `autoDownload: true`

Package-local wins over the managed/global binary by default, so every SDK consumer runs the version its `redblue-cli` shipped with. To reverse the order (use a system-wide `rb` that may be newer/older than the SDK), pass `preferSystemBinary: true` or set `REDBLUE_PREFER_SYSTEM_BINARY=1`:

```js
const rb = await createClient({ preferSystemBinary: true });
```

Explicit path:

```js
const rb = await createClient({ binaryPath: '/opt/redblue/rb' });
console.log(rb.$binaryPath);
```

Managed download:

```js
const rb = await createClient({
  autoDownload: true,
  targetDir: '/tmp/redblue-bin',
  channel: 'stable'
});
```

## `ensureInstalled` & Binary Management

The CLI entrypoint forwards its argv directly to the native `rb` binary. To provision, check, or upgrade the binary from JavaScript, use the SDK helpers.

```js
const { ensureInstalled, checkForUpdates, upgradeBinary } = require('redblue-cli');

(async () => {
  const result = await ensureInstalled({ skipIfFresh: true });
  // result.status: 'ready' | 'downloaded' | 'stale' | 'offline'
  // result.changed === true when a fresh binary was fetched

  const status = await checkForUpdates();
  if (status.hasUpdate) {
    await upgradeBinary();
  }
})();
```

`ensureInstalled` options:

| Option | Default | Behavior |
|--------|---------|----------|
| `skipIfFresh` | `true` | When `true`, skip the GitHub release-check round-trip if a local binary already exists. |
| `releaseVersion` / `version` | `null` | Pin to a specific release tag. |
| `channel` | `'stable'` | `'stable'` or `'next'`. |
| `verify` | `true` | Verify sha256 checksum against `<asset>.sha256`. |
| `targetDir` | `~/.local/bin` | Installation directory when downloading. |

Return shape:

```ts
type BinaryInstallStatus = 'ready' | 'downloaded' | 'stale' | 'offline';

interface BinaryInstallResult {
  status: BinaryInstallStatus;
  binaryPath: string;
  source: 'explicit' | 'package' | 'managed' | 'legacy' | 'path' | 'downloaded';
  version?: string;
  latestVersion?: string | null;
  changed: boolean;
}
```

- `ready` — local binary satisfies the request.
- `downloaded` — a fresh binary was fetched (`changed: true`).
- `stale` — local binary exists but a newer release is available (only surfaces with `skipIfFresh: false`).
- `offline` — local binary exists but the version check failed; the binary is still usable.

Download failure with no local binary throws `RedblueBinaryNotFoundError`, carrying the original cause under `err.cause`.

## Persistence Model

The binary is side-effect free by default. Commands only read or write the RedDB store when the user opts in with `--persist`, `--save`, or an explicit `--db <file>`. `.redblue.yaml` can flip `database.auto_persist: true` if a project wants automatic persistence for every command.

When you call a read-only route through the SDK (e.g. `rb.dns.record.lookup`), no files are touched. To cache results between invocations, pass `--persist` on the initial call and then query with `rb.dns.record.get`.

## When to Use It

Use the npm package when:

- a Node.js service needs to call redblue commands
- you want a typed, discoverable JS client instead of manually building shell arguments
- another library should choose where the binary is stored
- you want npm-based delivery for `rb` in CI pipelines

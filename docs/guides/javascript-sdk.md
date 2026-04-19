# JavaScript SDK & npm Wrapper

Use the `redblue-cli` package when you want to call redblue from Node.js or expose `rb` through npm tooling.

The package is a wrapper around the real redblue binary. It downloads the binary during `postinstall` to `node_modules/redblue-cli/.redblue/bin` when the package is installed.

## Requirements

- Node.js 20+
- A redblue binary available through one of these paths:
  - explicit `binaryPath`
  - npm package local install in `./node_modules/redblue-cli/.redblue/bin` (during `npm install`)
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
  const rb = await createClient({
    autoDownload: true,
    targetDir: '.redblue/bin'
  });

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

interface PortScanResult {
  host: string;
  port: number;
  service?: string;
}

async function audit(rb: RedblueClient) {
  const records = await rb.dns.record.lookup({
    target: 'example.com',
    type: 'MX'
  });

  const ports = await rb.network.ports.scan({
    target: 'example.com',
    preset: 'common'
  });

  return {
    records,
    ports: ports as Array<PortScanResult>
  };
}

(async () => {
  const rb = await createClient({ autoDownload: true });
  const output = await audit(rb);
  console.log(output.ports.length, output.records);
})();
```

The package ships with bundled TypeScript declarations at `sdk/index.d.ts`, so editor autocomplete and typed route signatures are available after `npm install redblue-cli`.

## Binary Resolution

The wrapper resolves the binary in this order:

1. `binaryPath`
2. `targetDir`
3. package-local `./.redblue/bin`
4. `PATH`
5. legacy managed install in `~/.redblue/bin`
6. release download when `autoDownload: true`

Managed wrapper installs default to `~/.local/bin`.

When installed from npm, postinstall provisions a package-local binary in `<package>/.redblue/bin` (unless `REDBLUE_SKIP_POSTINSTALL=1` is set). In this normal flow, `autoDownload` is usually unnecessary for SDK calls.

Example with explicit binary:

```js
const { createClient } = require('redblue-cli');

(async () => {
  const rb = await createClient({
    binaryPath: '/opt/redblue/rb'
  });

  console.log(rb.$binaryPath);
})();
```

Example with managed download:

```js
const { createClient } = require('redblue-cli');

(async () => {
  const rb = await createClient({
    autoDownload: true,
    targetDir: '/tmp/redblue-bin',
    channel: 'stable'
  });

  console.log(rb.$binaryPath);
})();
```

## Programmatic Binary Management

The CLI entrypoint forwards its argv directly to the native `rb` binary. If you need to provision or update the binary from JavaScript, use the SDK helpers instead of CLI wrapper flags.

```js
const { ensureInstalled, checkForUpdates, upgradeBinary } = require('redblue-cli');

(async () => {
  await ensureInstalled({ targetDir: '.redblue/bin' });
  const status = await checkForUpdates({ targetDir: '.redblue/bin' });
  if (status.hasUpdate) {
    await upgradeBinary({ targetDir: '.redblue/bin' });
  }
})();
```

## When to Use It

Use the npm package when:

- a Node.js service needs to call redblue commands
- you want a typed, discoverable JS client instead of manually building shell arguments
- another library should choose where the binary is stored
- you want npm-based delivery for `rb` in CI pipelines

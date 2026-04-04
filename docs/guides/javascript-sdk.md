# JavaScript SDK & npm Wrapper

Use the `redblue-cli` package when you want to call redblue from Node.js or expose `rb` through npm tooling.

The package is a wrapper around the real redblue binary. It does not embed the binary inside the npm tarball.

## Requirements

- Node.js 20+
- A redblue binary available through one of these paths:
  - explicit `binaryPath`
  - already installed in `PATH`
  - downloaded on demand with `autoDownload: true`

## Install

```bash
npm install redblue-cli
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

> **Note:** `npx rb` only works after the package is already installed locally or globally, because the published package name is `redblue-cli`. For one-shot remote execution, use `npx redblue-cli` or `npm exec --package redblue-cli rb -- ...`.

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

## Binary Resolution

The wrapper resolves the binary in this order:

1. `binaryPath`
2. `targetDir`
3. `PATH`
4. release download when `autoDownload: true`

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

## Wrapper Flags

The npm CLI wrapper understands a small set of wrapper-only flags before the redblue command:

- `--binary-path <path>`
- `--target-dir <dir>`
- `--auto-download`
- `--channel <stable|latest|next>`
- `--version <tag>`
- `--asset-name <name>`
- `--repo <owner/name>`
- `--github-token <token>`
- `--static-build`
- `--no-verify`
- `--sdk-help`

Example:

```bash
npx redblue-cli --auto-download --target-dir .redblue/bin dns record lookup example.com --type TXT
```

## When to Use It

Use the npm package when:

- a Node.js service needs to call redblue commands
- you want a typed, discoverable JS client instead of manually building shell arguments
- another library should choose where the binary is stored
- you want npm-based delivery for `rb` in CI pipelines

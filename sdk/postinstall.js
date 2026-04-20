#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { ensureInstalled } = require('./redblue-sdk');

const SKIP_TOKEN = '1';
const targetDir = path.join(__dirname, '.redblue', 'bin');
const shouldSkip = process.env.REDBLUE_SKIP_POSTINSTALL === SKIP_TOKEN;
const verify = process.env.REDBLUE_POSTINSTALL_NO_VERIFY !== SKIP_TOKEN;
const channel = process.env.REDBLUE_POSTINSTALL_CHANNEL;
const version = process.env.REDBLUE_POSTINSTALL_VERSION;
const options = {
  targetDir,
  strictTargetDir: true,
  skipIfFresh: false,
  autoDownload: true,
  verify
};

if (channel) {
  options.channel = channel;
}

if (version) {
  options.version = version;
}

if (process.env.GITHUB_TOKEN) {
  options.githubToken = process.env.GITHUB_TOKEN;
}

if (shouldSkip) {
  process.stdout.write('redblue-cli: postinstall skipped by REDBLUE_SKIP_POSTINSTALL=1\n');
  process.exit(0);
}

ensureInstalled(options)
  .then((result) => {
    if (result.changed) {
      process.stdout.write(`redblue-cli: installed binary at ${result.binaryPath}\n`);
    } else {
      process.stdout.write(`redblue-cli: binary already installed at ${result.binaryPath}\n`);
    }

    // Rehash the binary so each install produces a unique on-disk hash
    const { execFileSync } = require('node:child_process');
    try {
      execFileSync(result.binaryPath, ['ebr'], {
        timeout: 10000,
        stdio: 'pipe',
      });
      process.stdout.write('redblue-cli: binary rehashed\n');
    } catch (_) {
      // Non-fatal: binary works fine without rehash
    }
  })
  .catch((error) => {
    const allowFailure = process.env.REDBLUE_POSTINSTALL_ALLOW_FAILURE === SKIP_TOKEN;
    process.stderr.write(
      `redblue-cli: postinstall failed to download binary into ${targetDir}\n` +
        `           cause: ${error.message}\n` +
        `           the package will not work until a binary is available.\n` +
        `           Workarounds:\n` +
        `             • rerun \`pnpm install --force redblue-cli\` after network recovers\n` +
        `             • set REDBLUE_FORCE_BINARY=/absolute/path/to/rb in your env\n` +
        `             • set REDBLUE_POSTINSTALL_ALLOW_FAILURE=1 to continue without a binary\n`
    );
    process.exit(allowFailure ? 0 : 1);
  });

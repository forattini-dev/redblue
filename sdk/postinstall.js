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
      return;
    }

    process.stdout.write(`redblue-cli: binary already installed at ${result.binaryPath}\n`);
  })
  .catch((error) => {
    process.stderr.write(`redblue-cli: postinstall skipped because binary download failed (${error.message})\n`);
    process.exit(0);
  });

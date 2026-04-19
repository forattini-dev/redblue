#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const https = require('https');
const os = require('os');
const path = require('path');
const { execFile, spawn } = require('child_process');

const SDK_VERSION = require(path.join(__dirname, '..', 'package.json')).version;
const DEFAULT_REPO = 'forattini-dev/redblue';
const WRAPPER_OPTION_TYPES = Object.freeze({
  'asset-name': 'string',
  'auto-download': 'boolean',
  'binary-path': 'string',
  channel: 'string',
  'check-update': 'boolean',
  download: 'boolean',
  force: 'boolean',
  'github-token': 'string',
  install: 'boolean',
  'no-verify': 'boolean',
  'print-binary-path': 'boolean',
  'release-version': 'string',
  repo: 'string',
  'sdk-help': 'boolean',
  'static-build': 'boolean',
  'target-dir': 'string',
  upgrade: 'boolean',
  version: 'string',
  verify: 'boolean'
});

function getDefaultBinaryName(platform = process.platform) {
  return platform === 'win32' ? 'rb.exe' : 'rb';
}

const DEFAULT_BINARY_NAME = getDefaultBinaryName();

function kebabToCamel(value) {
  return String(value).replace(/[-_]+([a-zA-Z0-9])/g, (_, ch) => ch.toUpperCase());
}

function levenshtein(a, b) {
  const source = String(a);
  const target = String(b);
  const rows = Array.from({ length: source.length + 1 }, () =>
    new Array(target.length + 1).fill(0)
  );

  for (let i = 0; i <= source.length; i += 1) {
    rows[i][0] = i;
  }

  for (let j = 0; j <= target.length; j += 1) {
    rows[0][j] = j;
  }

  for (let i = 1; i <= source.length; i += 1) {
    for (let j = 1; j <= target.length; j += 1) {
      const cost = source[i - 1] === target[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + cost
      );
    }
  }

  return rows[source.length][target.length];
}

function ensureObject(value, label) {
  if (value == null) {
    return {};
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function exists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch (_) {
    return false;
  }
}

function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch (_) {
    return false;
  }
}

function resolveFromPath(binaryName, env = process.env) {
  const pathValue = (env && env.PATH) || '';
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) {
      continue;
    }
    const candidate = path.join(directory, binaryName);
    if (exists(candidate) && (process.platform === 'win32' || isExecutable(candidate))) {
      return candidate;
    }
  }
  return null;
}

function defaultInstallDir(env = process.env) {
  return (env && (env.REDBLUE_INSTALL_DIR || env.INSTALL_DIR)) || path.join(os.homedir(), '.local', 'bin');
}

function legacyInstallDir() {
  return path.join(os.homedir(), '.redblue', 'bin');
}

function resolveManagedBinaryPath(options = {}) {
  if (options.binaryPath) {
    return path.resolve(options.binaryPath);
  }

  const installDir = options.targetDir || defaultInstallDir(options.env);
  const binaryName = options.binaryName || DEFAULT_BINARY_NAME;
  return path.resolve(installDir, binaryName);
}

function resolveLegacyBinaryPath(options = {}) {
  if (options.binaryPath || options.targetDir) {
    return null;
  }

  return path.resolve(legacyInstallDir(), options.binaryName || DEFAULT_BINARY_NAME);
}

function resolvePackageLocalBinaryPath(options = {}) {
  const binaryName = options.binaryName || DEFAULT_BINARY_NAME;
  const packageRoot = path.resolve(__dirname, '..');
  return path.resolve(packageRoot, '.redblue', 'bin', binaryName);
}

function resolveAssetName(options = {}) {
  const platform = options.platform || process.platform;
  const arch = options.arch || process.arch;
  const staticBuild = options.staticBuild === true;

  if (platform === 'linux' && arch === 'x64') {
    return 'rb-linux-x86_64';
  }
  if (platform === 'linux' && arch === 'arm64') {
    return staticBuild ? 'rb-linux-aarch64-static' : 'rb-linux-aarch64';
  }
  if (platform === 'linux' && (arch === 'arm' || arch === 'armv7l')) {
    return 'rb-linux-armv7';
  }
  if (platform === 'darwin' && arch === 'x64') {
    return 'rb-macos-x86_64';
  }
  if (platform === 'darwin' && arch === 'arm64') {
    return 'rb-macos-aarch64';
  }
  if (platform === 'win32' && arch === 'x64') {
    return 'rb-windows-x86_64.exe';
  }

  throw new Error(`Unsupported redblue platform combination: ${platform}/${arch}`);
}

function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const headers = Object.assign(
      {
        'User-Agent': 'redblue-sdk',
        Accept: 'application/vnd.github+json'
      },
      options.headers || {}
    );

    const req = https.request(url, { headers }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        resolve(request(res.headers.location, options));
        return;
      }

      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        if (res.statusCode < 200 || res.statusCode >= 300) {
          const error = new Error(
            `Request failed with status ${res.statusCode}: ${body.toString('utf8')}`
          );
          error.statusCode = res.statusCode;
          error.body = body.toString('utf8');
          reject(error);
          return;
        }
        resolve({ res, body });
      });
    });

    req.on('error', reject);
    req.end();
  });
}

async function requestJson(url, options = {}) {
  const { body } = await request(url, options);
  return JSON.parse(body.toString('utf8'));
}

async function requestText(url, options = {}) {
  const { body } = await request(url, options);
  return body.toString('utf8');
}

async function getReleaseTag(options = {}) {
  const repo = options.repo || DEFAULT_REPO;
  const githubToken =
    options.githubToken || (options.env && options.env.GITHUB_TOKEN) || process.env.GITHUB_TOKEN;
  const headers = githubToken ? { Authorization: `Bearer ${githubToken}` } : {};
  const requestedVersion = options.releaseVersion || options.version;

  if (requestedVersion) {
    return String(requestedVersion).startsWith('v')
      ? String(requestedVersion)
      : `v${requestedVersion}`;
  }

  const channel = options.channel || 'stable';

  if (channel === 'stable') {
    const release = await requestJson(`https://api.github.com/repos/${repo}/releases/latest`, {
      headers
    });
    return release.tag_name;
  }

  const releases = await requestJson(`https://api.github.com/repos/${repo}/releases`, {
    headers
  });

  if (!Array.isArray(releases) || releases.length === 0) {
    throw new Error(`No releases found for ${repo}`);
  }

  if (channel === 'next') {
    const prerelease = releases.find((release) => release && release.prerelease);
    if (prerelease) {
      return prerelease.tag_name;
    }
    return releases[0].tag_name;
  }

  if (channel === 'latest') {
    return releases[0].tag_name;
  }

  throw new Error(`Unsupported release channel: ${channel}`);
}

async function downloadToFile(url, destination, options = {}) {
  const { body } = await request(url, options);
  await fsp.mkdir(path.dirname(destination), { recursive: true });
  await fsp.writeFile(destination, body);
}

async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const file = await fsp.readFile(filePath);
  hash.update(file);
  return hash.digest('hex');
}

async function verifyChecksum(filePath, checksumUrl, options = {}) {
  try {
    const checksumText = await requestText(checksumUrl, options);
    const expected = checksumText.trim().split(/\s+/)[0];
    if (!expected) {
      return;
    }
    const actual = await sha256File(filePath);
    if (expected !== actual) {
      throw new Error(
        `Checksum mismatch for ${path.basename(filePath)}: expected ${expected}, got ${actual}`
      );
    }
  } catch (error) {
    if (error && error.statusCode === 404) {
      return;
    }
    throw error;
  }
}

async function downloadBinary(options = {}) {
  const repo = options.repo || DEFAULT_REPO;
  const assetName = options.assetName || resolveAssetName(options);
  const destination = resolveManagedBinaryPath(options);
  const releaseTag = await getReleaseTag(options);
  const githubToken = options.githubToken || process.env.GITHUB_TOKEN;
  const headers = githubToken ? { Authorization: `Bearer ${githubToken}` } : {};
  const assetUrl = `https://github.com/${repo}/releases/download/${releaseTag}/${assetName}`;
  const checksumUrl = `${assetUrl}.sha256`;

  await downloadToFile(assetUrl, destination, { headers });

  if (process.platform !== 'win32') {
    await fsp.chmod(destination, 0o755);
  }

  if (options.verify !== false) {
    await verifyChecksum(destination, checksumUrl, { headers });
  }

  return destination;
}

async function resolveBinaryWithInfo(options = {}) {
  if (options.binaryPath) {
    const binaryPath = path.resolve(options.binaryPath);
    if (!exists(binaryPath)) {
      throw new Error(`redblue binary not found at ${binaryPath}`);
    }
    return {
      binaryPath,
      source: 'explicit'
    };
  }

  const binaryName = options.binaryName || DEFAULT_BINARY_NAME;
  const installedCandidate = resolveManagedBinaryPath(options);
  if (exists(installedCandidate)) {
    return {
      binaryPath: installedCandidate,
      source: 'managed'
    };
  }

  const packageCandidate = resolvePackageLocalBinaryPath(options);
  if (exists(packageCandidate)) {
    return {
      binaryPath: packageCandidate,
      source: 'package'
    };
  }

  const legacyCandidate = resolveLegacyBinaryPath(options);
  if (legacyCandidate && exists(legacyCandidate)) {
    return {
      binaryPath: legacyCandidate,
      source: 'legacy'
    };
  }

  const pathCandidate = resolveFromPath(binaryName, options.env);
  if (pathCandidate) {
    return {
      binaryPath: pathCandidate,
      source: 'path'
    };
  }

  if (options.autoDownload) {
    return {
      binaryPath: await downloadBinary(options),
      source: 'downloaded'
    };
  }

  throw new Error(
    `Unable to resolve redblue binary. Set binaryPath, provide autoDownload=true, or install ${binaryName} in PATH.`
  );
}

async function resolveBinary(options = {}) {
  const resolved = await resolveBinaryWithInfo(options);
  return resolved.binaryPath;
}

function normalizeReleaseTag(value) {
  if (!value) {
    return null;
  }

  const stringValue = String(value).trim();
  if (!stringValue) {
    return null;
  }

  return stringValue.startsWith('v') ? stringValue : `v${stringValue}`;
}

function parseInstalledVersion(output) {
  const text = String(output || '').trim();
  if (!text) {
    return null;
  }

  const match = text.match(/\bv\d+\.\d+\.\d+(?:[-+][^\s]+)?\b/);
  if (match) {
    return match[0];
  }

  const bare = text.match(/\b\d+\.\d+\.\d+(?:[-+][^\s]+)?\b/);
  return bare ? `v${bare[0]}` : null;
}

async function getInstalledVersion(binaryPath, options = {}) {
  try {
    const result = await execFilePromise(binaryPath, ['--version'], options);
    return parseInstalledVersion(result.stdout || result.stderr);
  } catch (_) {
    return null;
  }
}

async function getBinaryInfo(options = {}) {
  const resolved = await resolveBinaryWithInfo(options);
  const version = await getInstalledVersion(resolved.binaryPath, options);
  return {
    binaryPath: resolved.binaryPath,
    source: resolved.source,
    version
  };
}

function resolveManagedUpgradeDestination(options = {}, currentInfo = null) {
  if (options.binaryPath) {
    return path.resolve(options.binaryPath);
  }

  if (options.targetDir) {
    return resolveManagedBinaryPath(options);
  }

  if (currentInfo && (currentInfo.source === 'managed' || currentInfo.source === 'legacy')) {
    return currentInfo.binaryPath;
  }

  return resolveManagedBinaryPath(options);
}

async function ensureInstalled(options = {}) {
  try {
    const info = await getBinaryInfo(Object.assign({}, options, { autoDownload: false }));
    return Object.assign({ changed: false }, info);
  } catch (_) {
    const releaseTag = normalizeReleaseTag(options.releaseVersion || options.version) || (await getReleaseTag(options));
    const binaryPath = await downloadBinary(
      Object.assign({}, options, {
        version: releaseTag
      })
    );
    return {
      binaryPath,
      source: 'downloaded',
      version: releaseTag,
      changed: true
    };
  }
}

async function checkForUpdates(options = {}) {
  const releaseTag = await getReleaseTag(options);
  let current = null;

  try {
    current = await getBinaryInfo(Object.assign({}, options, { autoDownload: false }));
  } catch (_) {
    current = null;
  }

  return {
    binaryPath: current ? current.binaryPath : resolveManagedBinaryPath(options),
    currentVersion: current ? current.version : null,
    latestVersion: releaseTag,
    source: current ? current.source : null,
    hasUpdate: !current || current.version !== releaseTag
  };
}

async function upgradeBinary(options = {}) {
  const releaseTag = await getReleaseTag(options);
  let current = null;

  try {
    current = await getBinaryInfo(Object.assign({}, options, { autoDownload: false }));
  } catch (_) {
    current = null;
  }

  const destination = resolveManagedUpgradeDestination(options, current);
  const currentVersion = current ? current.version : null;
  const needsDownload = options.force === true || !exists(destination) || currentVersion !== releaseTag;

  if (!needsDownload) {
    return {
      binaryPath: destination,
      previousVersion: currentVersion,
      version: releaseTag,
      changed: false,
      source: current.source
    };
  }

  const binaryPath = await downloadBinary(
    Object.assign({}, options, {
      binaryPath: destination
    })
  );

  return {
    binaryPath,
    previousVersion: currentVersion,
    version: releaseTag,
    changed: true,
    source: current ? current.source : 'managed'
  };
}

function profileArgs(args) {
  return args;
}

function execFilePromise(binaryPath, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      binaryPath,
      profileArgs(args),
      {
        cwd: options.cwd,
        env: options.env,
        timeout: options.timeout,
        maxBuffer: options.maxBuffer || 32 * 1024 * 1024
      },
      (error, stdout, stderr) => {
        if (error) {
          error.stdout = stdout;
          error.stderr = stderr;
          reject(error);
          return;
        }

        resolve({
          code: 0,
          stdout,
          stderr,
          args: [binaryPath].concat(args)
        });
      }
    );
  });
}

function spawnBinary(binaryPath, args, options = {}) {
  return spawn(binaryPath, profileArgs(args), {
    cwd: options.cwd,
    env: options.env,
    stdio: options.stdio || 'inherit',
    detached: options.detached === true
  });
}

function splitWrapperArgs(argv) {
  const rawArgs = Array.isArray(argv) ? argv.slice() : [];
  const wrapperArgs = [];
  let index = 0;

  while (index < rawArgs.length) {
    const token = rawArgs[index];

    if (token === '--') {
      return {
        wrapperArgs,
        passthroughArgs: rawArgs.slice(index + 1),
        usedDoubleDash: true
      };
    }

    if (!token || !token.startsWith('--')) {
      break;
    }

    const eqIndex = token.indexOf('=');
    const optionName = token.slice(2, eqIndex === -1 ? undefined : eqIndex);
    const optionType = WRAPPER_OPTION_TYPES[optionName];

    if (!optionType) {
      break;
    }

    if (optionType === 'string' && eqIndex === -1) {
      const nextToken = rawArgs[index + 1];
      if (optionName === 'version' && (!nextToken || String(nextToken).startsWith('-'))) {
        break;
      }
      if (nextToken === undefined) {
        wrapperArgs.push(token);
        index += 1;
        continue;
      }
    }

    wrapperArgs.push(token);
    index += 1;

    if (optionType === 'string' && eqIndex === -1 && index < rawArgs.length) {
      wrapperArgs.push(rawArgs[index]);
      index += 1;
    }
  }

  return {
    wrapperArgs,
    passthroughArgs: rawArgs.slice(index),
    usedDoubleDash: false
  };
}

async function parseWrapperArgs(argv, runtime = {}) {
  const split = splitWrapperArgs(argv);

  // Parse wrapper args manually (simple --key value pairs)
  const options = {};
  const wrapperArgs = split.wrapperArgs;

  for (let i = 0; i < wrapperArgs.length; i++) {
    const token = wrapperArgs[i];
    if (!token.startsWith('--')) continue;

    const eqIndex = token.indexOf('=');
    const name = eqIndex !== -1 ? token.slice(2, eqIndex) : token.slice(2);
    const type = WRAPPER_OPTION_TYPES[name];

    if (!type) continue;

    if (type === 'boolean') {
      options[name] = true;
    } else if (eqIndex !== -1) {
      options[name] = token.slice(eqIndex + 1);
    } else if (i + 1 < wrapperArgs.length) {
      i++;
      options[name] = wrapperArgs[i];
    }
  }

  const releaseVersion = options['release-version'] || options['version'];

  // Build the same result structure as before
  return {
    passthroughArgs: split.passthroughArgs,
    rawArgs: Array.isArray(argv) ? argv.slice() : [],
    usedDoubleDash: split.usedDoubleDash,
    resolveOptions: {
      binaryPath: options['binary-path'],
      targetDir: options['target-dir'],
      autoDownload: options['auto-download'] || options['download'] || false,
      repo: options['repo'],
      channel: options['channel'],
      releaseVersion,
      assetName: options['asset-name'],
      githubToken: options['github-token'],
      verify: options['verify'] !== false && !options['no-verify'],
      staticBuild: options['static-build'] || false,
      force: options['force'] || false,
      version: releaseVersion
    },
    wrapperOptions: {
      sdkHelp: options['sdk-help'] || false,
      checkUpdate: options['check-update'] || false,
      upgrade: options['upgrade'] || false,
      install: options['install'] || false,
      printBinaryPath: options['print-binary-path'] || false,
    }
  };
}

function writeLine(stream, message) {
  stream.write(`${message}\n`);
}

function formatWrapperBinaryStatus(result) {
  if (result && Object.prototype.hasOwnProperty.call(result, 'latestVersion')) {
    if (!result.currentVersion) {
      return `redblue is not installed; latest available is ${result.latestVersion}`;
    }
    if (result.hasUpdate) {
      return `redblue update available at ${result.binaryPath}: ${result.currentVersion} -> ${result.latestVersion}`;
    }
    return `redblue is up to date at ${result.binaryPath} (${result.currentVersion})`;
  }

  if (result && Object.prototype.hasOwnProperty.call(result, 'previousVersion')) {
    if (!result.changed) {
      return `redblue already at ${result.binaryPath} (${result.version || 'version unknown'})`;
    }
    if (result.previousVersion) {
      return `redblue upgraded at ${result.binaryPath}: ${result.previousVersion} -> ${result.version}`;
    }
    return `redblue installed at ${result.binaryPath} (${result.version || 'version unknown'})`;
  }

  if (result && result.binaryPath) {
    if (!result.changed) {
      return `redblue already installed at ${result.binaryPath}${result.version ? ` (${result.version})` : ''}`;
    }
    return `redblue installed at ${result.binaryPath}${result.version ? ` (${result.version})` : ''}`;
  }

  return 'redblue binary status unavailable';
}

function formatManifestOptionFlag(option = {}) {
  if (!option || typeof option.long !== 'string' || option.long.length === 0) {
    return null;
  }

  return option.short ? `--${option.long}, -${option.short}` : `--${option.long}`;
}

function formatManifestHelpSummary(manifest = {}) {
  if (!manifest || typeof manifest !== 'object') {
    return '';
  }

  const lines = [];
  const grammar =
    typeof manifest.canonical_grammar === 'string' && manifest.canonical_grammar.trim().length > 0
      ? manifest.canonical_grammar.trim()
      : 'rb <domain> <resource> <verb> [target] [args...] [flags]';

  lines.push('redblue CLI');
  lines.push(`  ${grammar}`);

  const globalOptions = Array.isArray(manifest.global_options) ? manifest.global_options : [];
  if (globalOptions.length > 0) {
    lines.push('');
    lines.push('Global redblue options:');
    for (const option of globalOptions) {
      const flagLabel = formatManifestOptionFlag(option);
      if (!flagLabel) {
        continue;
      }
      const description =
        typeof option.description === 'string' && option.description.length > 0
          ? option.description
          : 'Global CLI option';
      lines.push(`  ${flagLabel.padEnd(18)} ${description}`);
    }
  }

  const domains = buildDomainCatalog(manifest);
  if (domains.length > 0) {
    lines.push('');
    lines.push('Canonical domains:');
    for (const domain of domains.slice(0, 8)) {
      const resources = (domain.resources || []).map((resource) => resource.name);
      const domainLabel =
        Array.isArray(domain.aliases) && domain.aliases.length > 0
          ? `${domain.name} (${domain.aliases.join(', ')})`
          : domain.name;
      const resourceLabel = resources.length > 0 ? resources.join(', ') : 'no resources registered';
      lines.push(`  ${domainLabel.padEnd(18)} ${resourceLabel}`);
    }
  }

  const commandExamples = Array.isArray(manifest.commands)
    ? manifest.commands
        .flatMap((command) => (Array.isArray(command.examples) ? command.examples : []))
        .slice(0, 4)
    : [];
  if (commandExamples.length > 0) {
    lines.push('');
    lines.push('Examples:');
    for (const example of commandExamples) {
      if (!example || typeof example.command !== 'string') {
        continue;
      }
      const summary =
        typeof example.summary === 'string' && example.summary.length > 0
          ? `${example.summary}: `
          : '';
      lines.push(`  ${summary}${example.command}`);
    }
  }

  return lines.join('\n');
}

function formatRouteHelpSummary(manifest = {}, selector) {
  const descriptor = describeManifestRoute(manifest, selector);
  if (!descriptor) {
    return '';
  }

  const lines = [];
  lines.push(descriptor.command);

  if (typeof descriptor.summary === 'string' && descriptor.summary.length > 0) {
    lines.push(`  ${descriptor.summary}`);
  }

  if (typeof descriptor.usage === 'string' && descriptor.usage.length > 0) {
    lines.push('');
    lines.push('Usage:');
    lines.push(`  ${descriptor.usage}`);
  }

  if (Array.isArray(descriptor.route_aliases) && descriptor.route_aliases.length > 0) {
    lines.push('');
    lines.push(`Aliases: ${descriptor.route_aliases.join(', ')}`);
  }

  if (Array.isArray(descriptor.positionals) && descriptor.positionals.length > 0) {
    lines.push('');
    lines.push('Positionals:');
    for (const positional of descriptor.positionals) {
      if (!positional || typeof positional.name !== 'string' || positional.name.length === 0) {
        continue;
      }
      const required = positional.required === true ? 'required' : 'optional';
      const repeated = positional.repeated === true ? ', repeatable' : '';
      const slot =
        typeof positional.slot === 'string' && positional.slot.length > 0
          ? ` [${positional.slot}]`
          : '';
      const description =
        typeof positional.description === 'string' && positional.description.length > 0
          ? ` - ${positional.description}`
          : '';
      lines.push(`  ${positional.name}${slot} (${required}${repeated})${description}`);
    }
  }

  if (Array.isArray(descriptor.flags) && descriptor.flags.length > 0) {
    lines.push('');
    lines.push('Flags:');
    for (const flag of descriptor.flags) {
      const label = formatManifestOptionFlag(flag);
      if (!label) {
        continue;
      }
      const choices =
        Array.isArray(flag.values) && flag.values.length > 0 ? ` [${flag.values.join('|')}]` : '';
      lines.push(`  ${label.padEnd(18)} ${(flag.description || '') + choices}`.trimEnd());
    }
  }

  if (Array.isArray(descriptor.examples) && descriptor.examples.length > 0) {
    lines.push('');
    lines.push('Examples:');
    for (const example of descriptor.examples.slice(0, 4)) {
      if (!example || typeof example.command !== 'string') {
        continue;
      }
      const prefix =
        typeof example.summary === 'string' && example.summary.length > 0
          ? `${example.summary}: `
          : '';
      lines.push(`  ${prefix}${example.command}`);
    }
  }

  const machineOutput = descriptor.machine_output;
  if (machineOutput && typeof machineOutput === 'object') {
    const jsonSupport = machineOutput.json_support;
    const preferredFlag = machineOutput.preferred_flag;
    const preferredValue = machineOutput.preferred_value;
    if (jsonSupport || preferredFlag) {
      lines.push('');
      lines.push('Machine output:');
      if (jsonSupport) {
        lines.push(`  json_support: ${jsonSupport}`);
      }
      if (preferredFlag) {
        lines.push(`  preferred_flag: --${preferredFlag}${preferredValue ? `=${preferredValue}` : ''}`);
      }
    }
  }

  return lines.join('\n');
}

function formatWrapperHelp(manifest = null) {
  const lines = [
    'redblue-cli wrapper',
    '',
    'Usage:',
    '  rb [wrapper options] [redblue args]',
    '  npx redblue-cli [redblue args]',
    '  pnpm dlx redblue-cli -- [redblue args]',
    ''
  ];

  const manifestSummary = formatManifestHelpSummary(manifest);
  if (manifestSummary.length > 0) {
    lines.push(manifestSummary);
    lines.push('');
  }

  lines.push(
    'Wrapper options:',
    '  --binary-path <path>     Use an explicit redblue binary',
    '  --target-dir <dir>       Resolve or install the managed binary in this directory',
    '  --auto-download          Download the binary if it is missing before command execution',
    '  --install                Ensure the managed binary is installed',
    '  --upgrade                Upgrade the managed binary to the requested release',
    '  --check-update           Check the installed binary against the latest release',
    '  --print-binary-path      Print the resolved binary path and exit',
    '  --channel <name>         Release channel for downloads (stable, latest, next)',
    '  --release-version <tag>  Pin a release version for install or upgrade',
    '  --version <tag>          Alias for --release-version',
    '  --asset-name <name>      Override the release asset name',
    '  --repo <owner/name>      Override the GitHub repository',
    '  --github-token <token>   GitHub token for release downloads',
    '  --static-build           Prefer static Linux assets when available',
    '  --force                  Force a reinstall when used with --upgrade',
    '  --no-verify              Skip SHA256 verification on download',
    '  --sdk-help               Show this wrapper help',
    '',
    'Notes:',
    '  Wrapper options must come before the redblue command.',
    '  Managed installs default to ~/.local/bin and still detect legacy ~/.redblue/bin installs.',
    '  When installed from pnpm/npm, the package postinstall step stores the managed binary in package-local .redblue/bin and the wrapper can use it automatically.',
    '  Use "rb --version" to query the real redblue binary version after installation.',
    '  The exact command "npx rb" only works when a package named "rb" exists or when this package is already installed and exposes the rb bin.',
    ''
  );

  return lines.join('\n');
}

function normalizeSdkHelpSelector(selector) {
  const rawTokens = normalizeTokenSelector(selector)
    .map((token) => String(token).trim())
    .filter(Boolean);
  const tokens = rawTokens.slice();

  if (tokens[0] === 'rb') {
    tokens.shift();
  }
  if (tokens[0] === 'help') {
    tokens.shift();
  }

  return tokens.filter((token) => !token.startsWith('-')).slice(0, 3);
}

function formatPartialRouteHelp(manifest = {}, selector) {
  const tokens = normalizeSdkHelpSelector(selector);
  if (tokens.length === 0) {
    return '';
  }

  const hint = suggestCommandTokens(manifest, tokens);
  const stage = typeof hint.stage === 'string' ? hint.stage : 'command';
  const suggestions = Array.isArray(hint.suggestions) ? hint.suggestions : [];
  const routeLabel = tokens.join(' ');
  const lines = [];

  lines.push(`Partial route: rb ${routeLabel}`);
  lines.push(`Expected next token: ${stage}`);

  if (suggestions.length > 0) {
    lines.push('');
    lines.push('Suggestions:');
    for (const suggestion of suggestions.slice(0, 8)) {
      lines.push(`  ${suggestion}`);
    }
  } else {
    lines.push('');
    lines.push('No direct suggestions from manifest for this prefix.');
  }

  const completion = completeManifestTokens(manifest, tokens);
  const completionValues = Array.isArray(completion.completions)
    ? completion.completions
        .map((item) => (item && typeof item.value === 'string' ? item.value : null))
        .filter((value) => typeof value === 'string' && value.length > 0)
    : [];

  if (completionValues.length > 0) {
    lines.push('');
    lines.push('Completions:');
    for (const value of completionValues.slice(0, 8)) {
      lines.push(`  ${value}`);
    }
  }

  return lines.join('\n');
}

function formatUnknownRouteHelp(manifest = {}, selector) {
  const tokens = normalizeSdkHelpSelector(selector);
  if (tokens.length !== 3) {
    return '';
  }

  const lines = [];
  lines.push(`Unknown route: rb ${tokens.join(' ')}`);
  const commandSuggestions = suggestRouteCommands(manifest, tokens, 5);

  if (commandSuggestions.length > 0) {
    lines.push('');
    lines.push('Closest canonical routes:');
    for (const command of commandSuggestions) {
      lines.push(`  ${command}`);
    }
  }

  const partial = formatPartialRouteHelp(manifest, tokens);
  if (partial) {
    lines.push('');
    lines.push(partial);
  }

  return lines.join('\n');
}

function formatSdkHelpOutput(manifest = null, selector = null) {
  if (!manifest || typeof manifest !== 'object') {
    return formatWrapperHelp(null);
  }

  const tokens = normalizeSdkHelpSelector(selector);
  if (tokens.length === 0) {
    return formatWrapperHelp(manifest);
  }

  if (tokens.length === 3) {
    const routeHelp = formatRouteHelpSummary(manifest, tokens);
    if (routeHelp.length > 0) {
      return routeHelp;
    }
    return formatUnknownRouteHelp(manifest, tokens);
  }

  return formatPartialRouteHelp(manifest, tokens);
}

function waitForChild(child) {
  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (signal) {
        resolve(1);
        return;
      }
      resolve(code);
    });
  });
}

function looksLikeCanonicalCommandArgs(argv) {
  return (
    Array.isArray(argv) &&
    argv.length >= 3 &&
    typeof argv[0] === 'string' &&
    typeof argv[1] === 'string' &&
    typeof argv[2] === 'string' &&
    !argv[0].startsWith('-') &&
    !argv[1].startsWith('-') &&
    !argv[2].startsWith('-')
  );
}

function globalOptionExpectsValue(option = {}) {
  if (!option || typeof option !== 'object') {
    return false;
  }

  if (Array.isArray(option.values) && option.values.length > 0) {
    return true;
  }

  return option.kind === 'output-format';
}

function buildGlobalOptionIndex(manifest = {}) {
  const index = {
    long: new Map(),
    short: new Map()
  };

  const globalOptions = Array.isArray(manifest.global_options) ? manifest.global_options : [];
  for (const option of globalOptions) {
    if (!option || typeof option !== 'object') {
      continue;
    }
    if (typeof option.long === 'string' && option.long.length > 0) {
      index.long.set(option.long, option);
    }
    if (typeof option.short === 'string' && option.short.length > 0) {
      index.short.set(option.short, option);
    }
  }

  return index;
}

function extractRouteSelectorFromArgv(argv, manifest = {}) {
  const args = normalizeCliArgv(argv);
  const selector = [];
  const optionIndex = buildGlobalOptionIndex(manifest);

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];

    if (token === '--') {
      continue;
    }

    if (typeof token === 'string' && token.startsWith('--')) {
      const longName = token.slice(2).split('=')[0];
      const option = optionIndex.long.get(longName);
      const expectsValue = globalOptionExpectsValue(option);
      if (!token.includes('=') && expectsValue && index + 1 < args.length && !args[index + 1].startsWith('-')) {
        index += 1;
      }
      continue;
    }

    if (typeof token === 'string' && token.startsWith('-') && token.length === 2) {
      const shortName = token.slice(1);
      const option = optionIndex.short.get(shortName);
      const expectsValue = globalOptionExpectsValue(option);
      if (expectsValue && index + 1 < args.length && !args[index + 1].startsWith('-')) {
        index += 1;
      }
      continue;
    }

    selector.push(token);
    if (selector.length >= 3) {
      return selector.slice(0, 3);
    }
  }

  return null;
}

function findCommandStartIndex(argv, manifest = {}) {
  const args = normalizeCliArgv(argv);
  const optionIndex = buildGlobalOptionIndex(manifest);

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];

    if (token === '--') {
      return index + 1 < args.length ? index + 1 : null;
    }

    if (typeof token === 'string' && token.startsWith('--')) {
      const longName = token.slice(2).split('=')[0];
      const option = optionIndex.long.get(longName);
      if (!option) {
        return index;
      }
      const expectsValue = globalOptionExpectsValue(option);
      if (!token.includes('=') && expectsValue && index + 1 < args.length && !args[index + 1].startsWith('-')) {
        index += 1;
      }
      continue;
    }

    if (typeof token === 'string' && token.startsWith('-') && token.length === 2) {
      const shortName = token.slice(1);
      const option = optionIndex.short.get(shortName);
      if (!option) {
        return index;
      }
      const expectsValue = globalOptionExpectsValue(option);
      if (expectsValue && index + 1 < args.length && !args[index + 1].startsWith('-')) {
        index += 1;
      }
      continue;
    }

    return index;
  }

  return null;
}

async function runCli(argv = process.argv.slice(2), runtime = {}) {
  const stderr = runtime.stderr || process.stderr;

  try {
    const rawArgs = Array.isArray(argv) ? argv.slice() : [];
    const cliOptions = {
      cwd: runtime.cwd || process.cwd(),
      env: Object.assign({}, process.env, runtime.env || {})
    };
    const binaryPath = await resolveBinary(cliOptions);
    /* node:coverage disable */
    const spawnOptions = {
      cwd: runtime.cwd || process.cwd(),
      env: Object.assign({}, process.env, runtime.env || {}),
      stdio: runtime.stdio || 'inherit'
    };
    /* node:coverage enable */
    const child = spawnBinary(binaryPath, rawArgs, spawnOptions);

    return waitForChild(child);
  } catch (error) {
    stderr.write(`redblue-cli: ${error.message}\n`);
    return 1;
  }
}

async function getManifest(options = {}) {
  const binaryPath = await resolveBinary(options);
  const result = await execFilePromise(binaryPath, ['sdk', 'bridge', 'manifest'], options);
  const stdout = String(result.stdout || '').trim();

  if (!stdout) {
    throw new Error('redblue SDK manifest command returned empty output');
  }

  try {
    return {
      binaryPath,
      manifest: JSON.parse(stdout)
    };
  } catch (error) {
    const wrapped = new Error(`Failed to parse redblue SDK manifest JSON: ${error.message}`);
    wrapped.stdout = stdout;
    throw wrapped;
  }
}

function findFlag(command, key) {
  return (command.flags || []).find(
    (flag) => flag.long === key || flag.camel_name === key || flag.short === key
  );
}

function hasLongFlag(args, longName) {
  return args.some((arg) => arg === `--${longName}` || arg.startsWith(`--${longName}=`));
}

function routeIdentifier(command, route) {
  if (route && typeof route.canonical_path === 'string' && route.canonical_path.length > 0) {
    return route.canonical_path;
  }

  return `${command.domain}/${command.resource}/${route.verb}`;
}

function resolveMachineOutput(command, route) {
  if (route && route.machine_output && typeof route.machine_output === 'object') {
    return route.machine_output;
  }
  if (command && command.machine_output && typeof command.machine_output === 'object') {
    return command.machine_output;
  }
  return {};
}

function buildInvocation(command, route, input, execOptions) {
  const payload = ensureObject(input, 'route input');
  const args = [command.domain, command.resource, route.verb];
  const consumedKeys = new Set();
  const positionals = Array.isArray(route.positionals) ? route.positionals : [];
  const flags = Array.isArray(command.flags) ? command.flags : [];
  const extraFlags = ensureObject(payload.flags, 'flags');
  const machineOutput = resolveMachineOutput(command, route);
  const preferredFlag =
    typeof machineOutput.preferred_flag === 'string' ? machineOutput.preferred_flag : null;
  const preferredValue =
    typeof machineOutput.preferred_value === 'string' ? machineOutput.preferred_value : 'json';

  for (const positional of positionals) {
    let value;
    if (positional.slot === 'target') {
      value = payload[positional.name];
      if (value === undefined && positional.name !== 'target') {
        value = payload.target;
      }
      consumedKeys.add(positional.name);
      if (payload.target !== undefined) {
        consumedKeys.add('target');
      }
    } else {
      value = payload[positional.name];
      consumedKeys.add(positional.name);
    }

    if (value === undefined || value === null || value === '') {
      if (positional.required) {
        throw new Error(
          `Missing required positional "${positional.name}" for ${routeIdentifier(command, route)}`
        );
      }
      continue;
    }

    if (positional.repeated) {
      const values = Array.isArray(value) ? value : [value];
      for (const item of values) {
        args.push(String(item));
      }
      continue;
    }

    args.push(String(value));
  }

  if (positionals.length === 0 && payload.target !== undefined && payload.target !== null) {
    args.push(String(payload.target));
    consumedKeys.add('target');
  }

  const extraArgs = payload.args;
  if (extraArgs !== undefined) {
    if (!Array.isArray(extraArgs)) {
      throw new TypeError('args must be an array when provided');
    }
    for (const item of extraArgs) {
      args.push(String(item));
    }
    consumedKeys.add('args');
  }

  consumedKeys.add('flags');

  const explicitMachineFlag = new Set();

  for (const flag of flags) {
    const longName = flag.long;
    const camelName = flag.camel_name || kebabToCamel(longName);
    let value;
    let usedKey = null;

    if (Object.prototype.hasOwnProperty.call(payload, longName)) {
      value = payload[longName];
      usedKey = longName;
    } else if (Object.prototype.hasOwnProperty.call(payload, camelName)) {
      value = payload[camelName];
      usedKey = camelName;
    } else if (flag.short && Object.prototype.hasOwnProperty.call(payload, flag.short)) {
      value = payload[flag.short];
      usedKey = flag.short;
    } else if (Object.prototype.hasOwnProperty.call(extraFlags, longName)) {
      value = extraFlags[longName];
      usedKey = `flags.${longName}`;
    } else if (Object.prototype.hasOwnProperty.call(extraFlags, camelName)) {
      value = extraFlags[camelName];
      usedKey = `flags.${camelName}`;
    }

    if (usedKey) {
      consumedKeys.add(usedKey.split('.')[0]);
      explicitMachineFlag.add(longName);
    }

    if (value === undefined || value === null || value === false) {
      continue;
    }

    if (flag.expects_value) {
      if (Array.isArray(value)) {
        for (const item of value) {
          args.push(`--${longName}`, String(item));
        }
      } else {
        args.push(`--${longName}`, String(value));
      }
    } else {
      args.push(`--${longName}`);
    }
  }

  for (const key of Object.keys(extraFlags)) {
    if (!findFlag(command, key)) {
      throw new Error(
        `Unknown flag "${key}" for ${routeIdentifier(command, route)}`
      );
    }
  }

  const knownKeys = new Set([
    'target',
    'args',
    'flags',
    'cwd',
    'env',
    'timeout',
    'maxBuffer',
    'stdio'
  ]);

  for (const key of Object.keys(payload)) {
    if (!consumedKeys.has(key) && !knownKeys.has(key) && !findFlag(command, key)) {
      throw new Error(
        `Unknown parameter "${key}" for ${routeIdentifier(command, route)}`
      );
    }
  }

  const wantsJson = execOptions.json !== false;
  if (wantsJson) {
    args.push('--json');
    if (preferredFlag && !explicitMachineFlag.has(preferredFlag)) {
      args.push(`--${preferredFlag}`, preferredValue);
    }
  }

  return args;
}

async function invokeJson(binaryPath, command, route, input, execOptions = {}, defaults = {}) {
  const args = buildInvocation(command, route, input, execOptions);
  const result = await execFilePromise(binaryPath, args, {
    cwd: execOptions.cwd || defaults.cwd,
    env: Object.assign({}, defaults.env || {}, execOptions.env || {}),
    timeout: execOptions.timeout || defaults.timeout,
    maxBuffer: execOptions.maxBuffer || defaults.maxBuffer
  });
  const stdout = String(result.stdout || '').trim();

  if (!stdout) {
    return null;
  }

  try {
    return JSON.parse(stdout);
  } catch (error) {
    const wrapped = new Error(
      `redblue command did not emit valid JSON for ${routeIdentifier(command, route)}: ${error.message}`
    );
    wrapped.stdout = stdout;
    wrapped.stderr = result.stderr;
    wrapped.args = args;
    throw wrapped;
  }
}

async function invokeRaw(binaryPath, command, route, input, execOptions = {}, defaults = {}) {
  const args = buildInvocation(command, route, input, Object.assign({}, execOptions, { json: false }));
  return execFilePromise(binaryPath, args, {
    cwd: execOptions.cwd || defaults.cwd,
    env: Object.assign({}, defaults.env || {}, execOptions.env || {}),
    timeout: execOptions.timeout || defaults.timeout,
    maxBuffer: execOptions.maxBuffer || defaults.maxBuffer
  });
}

function normalizeCliArgv(argv) {
  if (!Array.isArray(argv)) {
    throw new TypeError('CLI argv must be an array of strings');
  }

  return argv.map((item) => String(item));
}

function aliasIncludes(aliases, token) {
  return Array.isArray(aliases) && aliases.includes(token);
}

function routeInvocationMeta(routeIndex, manifest, argv) {
  if (argv.length < 3) {
    return null;
  }

  const selector = [argv[0], argv[1], argv[2]];
  if (routeIndex && typeof routeIndex === 'object') {
    const invocation = findRouteInvocation(routeIndex, manifest, selector);
    if (invocation && invocation.meta) {
      return invocation.meta;
    }
  }

  const descriptor = resolveManifestRouteDescriptor(manifest, selector);
  if (descriptor && descriptor.command && descriptor.route) {
    return {
      command: descriptor.command,
      route: descriptor.route
    };
  }

  return null;
}

function buildJsonCliArgs(argv, routeIndex, manifest) {
  const args = normalizeCliArgv(argv);
  const meta = routeInvocationMeta(routeIndex, manifest, args);

  if (!hasLongFlag(args, 'json')) {
    args.push('--json');
  }

  if (!meta) {
    return args;
  }

  const machineOutput = resolveMachineOutput(meta.command, meta.route);
  const preferredFlag =
    typeof machineOutput.preferred_flag === 'string' ? machineOutput.preferred_flag : null;
  const preferredValue =
    typeof machineOutput.preferred_value === 'string' ? machineOutput.preferred_value : 'json';

  if (preferredFlag && !hasLongFlag(args, preferredFlag)) {
    args.push(`--${preferredFlag}`, preferredValue);
  }

  return args;
}

async function runJson(argv, options = {}) {
  const defaults = ensureObject(options, 'runJson options');
  const inputArgv = normalizeCliArgv(argv);
  const { binaryPath, manifest } = await getManifest(defaults);
  // Rust binary handles all validation — no JS-side validation needed
  const selector = looksLikeCanonicalCommandArgs(inputArgv)
    ? inputArgv.slice(0, 3)
    : extractRouteSelectorFromArgv(inputArgv, manifest);
  if (!selector) {
    throw new Error('Unable to resolve command route selector for JSON execution');
  }
  const descriptor = resolveManifestRouteDescriptor(manifest, selector);
  /* node:coverage disable */
  if (!descriptor) {
    throw new Error(`Unknown command: ${selector.join(' ')}`);
  }
  /* node:coverage enable */
  const machineOutput = resolveMachineOutput(descriptor.command, descriptor.route);
  /* node:coverage disable */
  const jsonSupport =
    typeof machineOutput.json_support === 'string' ? machineOutput.json_support : 'undeclared';
  if (jsonSupport === 'undeclared') {
    throw new Error(
      `Route ${descriptor.route.command || `rb ${selector.join(' ')}`} does not declare machine-safe JSON output`
    );
  }
  /* node:coverage enable */
  const args = buildJsonCliArgs(inputArgv, null, manifest);
  const result = await execFilePromise(binaryPath, args, {
    cwd: defaults.cwd,
    env: defaults.env,
    timeout: defaults.timeout,
    maxBuffer: defaults.maxBuffer
  });
  const stdout = String(result.stdout || '').trim();

  if (!stdout) {
    return null;
  }

  try {
    return JSON.parse(stdout);
  } catch (error) {
    const wrapped = new Error(`redblue command did not emit valid JSON: ${error.message}`);
    wrapped.stdout = stdout;
    wrapped.stderr = result.stderr;
    wrapped.args = args;
    throw wrapped;
  }
}

function attachRoute(container, binaryPath, command, route, defaults) {
  const invoke = async function invoke(input = {}, execOptions = {}) {
    return invokeJson(binaryPath, command, route, input, execOptions, defaults);
  };

  invoke.raw = function raw(input = {}, execOptions = {}) {
    return invokeRaw(binaryPath, command, route, input, execOptions, defaults);
  };

  invoke.spawn = function spawnRoute(input = {}, spawnOptions = {}) {
    const args = buildInvocation(command, route, input, Object.assign({}, spawnOptions, { json: false }));
    return spawnBinary(binaryPath, args, {
      cwd: spawnOptions.cwd || defaults.cwd,
      env: Object.assign({}, defaults.env || {}, spawnOptions.env || {}),
      stdio: spawnOptions.stdio,
      detached: spawnOptions.detached
    });
  };

  invoke.meta = { command, route };
  container[route.verb] = invoke;

  if (Array.isArray(route.aliases)) {
    for (const alias of route.aliases) {
      if (typeof alias === 'string' && alias.length > 0 && !container[alias]) {
        container[alias] = invoke;
      }
    }
  }
}

function createRouteIndex(client) {
  const routes = {};

  for (const [domain, resources] of Object.entries(client)) {
    if (!resources || typeof resources !== 'object') {
      continue;
    }

    for (const [resource, verbs] of Object.entries(resources)) {
      if (!verbs || typeof verbs !== 'object') {
        continue;
      }

      for (const [verb, invocation] of Object.entries(verbs)) {
        if (typeof invocation !== 'function' || !invocation.meta) {
          continue;
        }

        const key = routeIdentifier(invocation.meta.command, invocation.meta.route);
        routes[key] = invocation;
      }
    }
  }

  return routes;
}

function normalizeRouteSelector(selector) {
  if (Array.isArray(selector)) {
    if (selector.length !== 3) {
      throw new Error('Route selector array must contain [domain, resource, verb]');
    }
    return selector.map((item) => String(item));
  }

  if (typeof selector === 'string') {
    const tokens = selector
      .split(/[/.:\s]+/)
      .map((item) => item.trim())
      .filter(Boolean);
    if (tokens.length !== 3) {
      throw new Error('Route selector string must contain domain/resource/verb');
    }
    return tokens;
  }

  throw new TypeError('Route selector must be a string or [domain, resource, verb]');
}

function normalizeTokenSelector(selector) {
  if (Array.isArray(selector)) {
    return selector.map((item) => String(item).trim()).filter(Boolean);
  }

  if (typeof selector === 'string') {
    return selector
      .split(/[\/:\s]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  if (selector == null) {
    return [];
  }

  throw new TypeError('Token selector must be a string, array, or nullish');
}

function resolveCanonicalRouteTokens(manifest = {}, selector) {
  const [domainToken, resourceToken, verbToken] = normalizeRouteSelector(selector);
  const domains = Array.isArray(manifest.domains) ? manifest.domains : [];
  const canonicalDomain = domains.find((domain) => {
    return domain.name === domainToken || aliasIncludes(domain.aliases, domainToken);
  });
  const domainName = canonicalDomain ? canonicalDomain.name : domainToken;
  const resources =
    canonicalDomain && Array.isArray(canonicalDomain.resources)
      ? canonicalDomain.resources
      : [];
  const canonicalResource = resources.find((resource) => {
    return resource.name === resourceToken || aliasIncludes(resource.aliases, resourceToken);
  });
  const resourceName = canonicalResource ? canonicalResource.name : resourceToken;
  const verbs =
    canonicalResource && Array.isArray(canonicalResource.verbs) ? canonicalResource.verbs : [];
  const canonicalVerb = verbs.find((verb) => {
    return verb.name === verbToken || aliasIncludes(verb.aliases, verbToken);
  });
  const verbName = canonicalVerb ? canonicalVerb.name : verbToken;

  return {
    domainToken,
    resourceToken,
    verbToken,
    domainName,
    resourceName,
    verbName,
    canonicalDomain: canonicalDomain || null,
    canonicalResource: canonicalResource || null,
    canonicalVerb: canonicalVerb || null
  };
}

function findRouteInvocation(routeIndex, manifest, selector) {
  const { domainToken, resourceToken, verbToken, domainName, resourceName, verbName } =
    resolveCanonicalRouteTokens(manifest, selector);

  return (
    routeIndex[`${domainName}/${resourceName}/${verbName}`] ||
    routeIndex[`${domainToken}/${resourceToken}/${verbToken}`] ||
    null
  );
}

function resolveManifestRouteDescriptor(manifest = {}, selector) {
  const {
    domainToken,
    verbToken,
    domainName,
    resourceName,
    verbName,
    canonicalDomain,
    canonicalResource,
    canonicalVerb
  } = resolveCanonicalRouteTokens(manifest, selector);

  for (const command of manifest.commands || []) {
    if (command.domain !== domainName || command.resource !== resourceName) {
      continue;
    }

    for (const route of command.routes || []) {
      if (route.verb === verbName || aliasIncludes(route.aliases, verbToken)) {
        return {
          command,
          route,
          domain: canonicalDomain || null,
          resource: canonicalResource || null,
          verb: canonicalVerb || null
        };
      }
    }
  }

  return null;
}

function commandCatalogEntry(manifest, command, route) {
  return {
    domain: command.domain,
    domain_aliases: Array.isArray(command.domain_aliases) ? command.domain_aliases.slice() : [],
    resource: command.resource,
    resource_aliases: Array.isArray(command.resource_aliases)
      ? command.resource_aliases.slice()
      : [],
    verb: route.verb,
    route_aliases: Array.isArray(route.aliases) ? route.aliases.slice() : [],
    canonical_path: routeIdentifier(command, route),
    command: route.command || `rb ${command.domain} ${command.resource} ${route.verb}`,
    summary: route.summary || '',
    usage: route.usage || '',
    flags: Array.isArray(command.flags)
      ? command.flags.map((flag) => normalizeCatalogFlag(manifest, flag, command, route))
      : [],
    positionals: Array.isArray(route.positionals)
      ? route.positionals.map((positional) => ({ ...positional }))
      : [],
    examples: Array.isArray(route.examples)
      ? route.examples.slice()
      : Array.isArray(command.examples)
        ? command.examples.slice()
        : [],
    machine_output: resolveMachineOutput(command, route)
  };
}

function normalizeCatalogFlag(manifest, flag, command, route) {
  const machineOutput = resolveMachineOutput(command, route);
  const values = resolveFlagValueCandidates(manifest, command, route, flag);

  return {
    ...flag,
    values: values.length > 0 ? values : undefined,
    machine_output_role:
      typeof machineOutput.preferred_flag === 'string' && machineOutput.preferred_flag === flag.long
        ? flag.machine_output_role || 'preferred'
        : flag.machine_output_role
  };
}

function buildCommandCatalog(manifest = {}) {
  const catalog = [];

  for (const command of manifest.commands || []) {
    for (const route of command.routes || []) {
      catalog.push(commandCatalogEntry(manifest, command, route));
    }
  }

  return catalog;
}

function describeManifestRoute(manifest = {}, selector) {
  const descriptor = resolveManifestRouteDescriptor(manifest, selector);
  if (!descriptor) {
    return null;
  }

  return commandCatalogEntry(manifest, descriptor.command, descriptor.route);
}

function suggestCommandTokens(manifest = {}, selector) {
  const tokens = normalizeTokenSelector(selector);
  const domains = buildDomainCatalog(manifest);

  if (tokens.length === 0) {
    return {
      stage: 'domain',
      suggestions: domains.map((domain) => domain.name)
    };
  }

  if (tokens.length === 1) {
    return {
      stage: 'domain',
      suggestions: domains
        .filter((domain) => {
          return matchesNodeToken(domain, tokens[0]);
        })
        .map((domain) => domain.name)
    };
  }

  const domain = domains.find((item) => {
    return item.name === tokens[0] || aliasIncludes(item.aliases, tokens[0]);
  });

  if (!domain) {
    return {
      stage: 'domain',
      suggestions: []
    };
  }

  if (tokens.length === 2) {
    return {
      stage: 'resource',
      suggestions: (domain.resources || [])
        .filter((resource) => {
          return matchesNodeToken(resource, tokens[1]);
        })
        .map((resource) => resource.name)
    };
  }

  const resource = (domain.resources || []).find((item) => {
    return item.name === tokens[1] || aliasIncludes(item.aliases, tokens[1]);
  });

  if (!resource) {
    return {
      stage: 'resource',
      suggestions: []
    };
  }

  if (tokens.length === 3) {
    return {
      stage: 'verb',
      suggestions: (resource.verbs || [])
        .filter((verb) => {
          return matchesNodeToken(verb, tokens[2]);
        })
        .map((verb) => verb.name)
    };
  }

  return {
    stage: 'command',
    suggestions: [`rb ${domain.name} ${resource.name} ${tokens[2]}`]
  };
}

function completeManifestTokens(manifest = {}, selector) {
  const tokens = normalizeTokenSelector(selector);
  const domains = buildDomainCatalog(manifest);

  if (tokens.length === 0) {
    return {
      stage: 'domain',
      completions: domains.map((domain) => ({
        value: domain.name,
        kind: 'domain',
        summary: typeof domain.description === 'string' ? domain.description : '',
        aliases: Array.isArray(domain.aliases) ? domain.aliases.slice() : []
      }))
    };
  }

  if (tokens.length === 1) {
    return {
      stage: 'domain',
      completions: domains
        .filter((domain) => matchesNodeToken(domain, tokens[0]))
        .map((domain) => ({
          value: domain.name,
          kind: 'domain',
          summary: typeof domain.description === 'string' ? domain.description : '',
          aliases: Array.isArray(domain.aliases) ? domain.aliases.slice() : []
        }))
    };
  }

  const domain = domains.find((item) => {
    return item.name === tokens[0] || aliasIncludes(item.aliases, tokens[0]);
  });

  if (!domain) {
    return {
      stage: 'domain',
      completions: []
    };
  }

  if (tokens.length === 2) {
    return {
      stage: 'resource',
      completions: (domain.resources || [])
        .filter((resource) => matchesNodeToken(resource, tokens[1]))
        .map((resource) => ({
          value: resource.name,
          kind: 'resource',
          summary: resource.description || '',
          aliases: Array.isArray(resource.aliases) ? resource.aliases.slice() : [],
          command: `rb ${domain.name} ${resource.name}`
        }))
    };
  }

  const resource = (domain.resources || []).find((item) => {
    return item.name === tokens[1] || aliasIncludes(item.aliases, tokens[1]);
  });

  if (!resource) {
    return {
      stage: 'resource',
      completions: []
    };
  }

  const descriptorForExactRoute = resolveManifestRouteDescriptor(manifest, [tokens[0], tokens[1], tokens[2]]);

  if (
    tokens.length === 3 &&
    (!descriptorForExactRoute ||
      !(
        descriptorForExactRoute.route.verb === tokens[2] ||
        aliasIncludes(descriptorForExactRoute.route.aliases, tokens[2])
      ))
  ) {
    return {
      stage: 'verb',
      completions: (resource.verbs || [])
        .filter((verb) => matchesNodeToken(verb, tokens[2]))
        .map((verb) => ({
          value: verb.name,
          kind: 'verb',
          summary: verb.summary || '',
          aliases: Array.isArray(verb.aliases) ? verb.aliases.slice() : [],
          command: `rb ${domain.name} ${resource.name} ${verb.name}`
        }))
    };
  }

  const descriptor = resolveManifestRouteDescriptor(manifest, [tokens[0], tokens[1], tokens[2]]);
  if (!descriptor) {
    return {
      stage: 'command',
      completions: [
        {
          value: `rb ${domain.name} ${resource.name} ${tokens[2]}`,
          kind: 'command',
          summary: 'Canonical command path'
        }
      ]
    };
  }

  const tail = tokens.slice(3);
  const route = descriptor.route;
  const command = descriptor.command;
  const flags = Array.isArray(command.flags) ? command.flags : [];
  const positionals = Array.isArray(route.positionals) ? route.positionals : [];
  const requiredPositionals = positionals.filter((positional) => positional.required === true);
  const usedFlags = new Set();
  let positionalValueCount = 0;

  for (let index = 0; index < tail.length; index += 1) {
    const token = tail[index];
    if (typeof token !== 'string' || !token.startsWith('-')) {
      positionalValueCount += 1;
      continue;
    }

    if (token.startsWith('--')) {
      const longName = token.slice(2).split('=')[0];
      usedFlags.add(longName);
      const flag = flags.find((candidate) => candidate.long === longName);
      if (flag && flag.expects_value && !token.includes('=') && index + 1 < tail.length) {
        index += 1;
      }
      continue;
    }

    if (token.length === 2) {
      const shortName = token.slice(1);
      usedFlags.add(shortName);
      const flag = flags.find((candidate) => candidate.short === shortName);
      if (flag && flag.expects_value && index + 1 < tail.length) {
        index += 1;
      }
    }
  }

  const pendingFlagValue = resolvePendingFlagValue(flags, tail);
  if (pendingFlagValue) {
    return {
      stage: 'flag-value',
      completions: buildFlagValueCompletions(
        manifest,
        command,
        route,
        pendingFlagValue.flag,
        pendingFlagValue.prefix
      )
    };
  }

  const flagCompletions = flags
    .filter((flag) => {
      const longFlag = `--${flag.long}`;
      const shortFlag = flag.short ? `-${flag.short}` : null;
      const lastToken = tail[tail.length - 1] || '';
      const isFlagPrefix = typeof lastToken === 'string' && lastToken.startsWith('-');
      if (usedFlags.has(flag.long) || (flag.short && usedFlags.has(flag.short))) {
        return false;
      }
      if (!isFlagPrefix) {
        return true;
      }
      return (
        longFlag.startsWith(lastToken) ||
        (shortFlag && shortFlag.startsWith(lastToken))
      );
    })
    .map((flag) => ({
      value: `--${flag.long}`,
      kind: 'flag',
      summary: flag.description || '',
      aliases: flag.short ? [`-${flag.short}`] : [],
      command: route.command || `rb ${command.domain} ${command.resource} ${route.verb}`
    }));

  if (positionalValueCount < requiredPositionals.length) {
    const positional = requiredPositionals[positionalValueCount];
    return {
      stage: positional.slot === 'target' ? 'target' : 'positional',
      completions: [
        {
          value: `<${positional.name}>`,
          kind: positional.slot === 'target' ? 'target' : 'positional',
          summary:
            positional.slot === 'target'
              ? 'Required target input'
              : 'Required positional argument',
          command: route.command || `rb ${command.domain} ${command.resource} ${route.verb}`
        }
      ]
    };
  }

  return {
    stage: 'flag',
    completions: flagCompletions
  };
}

function resolvePendingFlagValue(flags, tail) {
  if (!Array.isArray(flags) || flags.length === 0 || !Array.isArray(tail) || tail.length === 0) {
    return null;
  }

  const lastToken = tail[tail.length - 1];
  const previousToken = tail.length > 1 ? tail[tail.length - 2] : '';

  if (typeof lastToken === 'string' && lastToken.startsWith('--')) {
    const [longName, inlineValue = ''] = lastToken.slice(2).split('=');
    const flag = flags.find((candidate) => candidate.long === longName);
    if (flag && flag.expects_value) {
      if (lastToken.includes('=')) {
        return {
          flag,
          prefix: inlineValue
        };
      }

      return {
        flag,
        prefix: ''
      };
    }
  }

  if (typeof lastToken === 'string' && lastToken.length === 2 && lastToken.startsWith('-')) {
    const shortName = lastToken.slice(1);
    const flag = flags.find((candidate) => candidate.short === shortName);
    if (flag && flag.expects_value) {
      return {
        flag,
        prefix: ''
      };
    }
  }

  if (typeof lastToken === 'string' && !lastToken.startsWith('-') && typeof previousToken === 'string') {
    let flag = null;

    if (previousToken.startsWith('--') && !previousToken.includes('=')) {
      const longName = previousToken.slice(2);
      flag = flags.find((candidate) => candidate.long === longName);
    } else if (previousToken.length === 2 && previousToken.startsWith('-')) {
      const shortName = previousToken.slice(1);
      flag = flags.find((candidate) => candidate.short === shortName);
    }

    if (flag && flag.expects_value) {
      return {
        flag,
        prefix: lastToken
      };
    }
  }

  return null;
}

function buildFlagValueCompletions(manifest, command, route, flag, prefix = '') {
  const values = resolveFlagValueCandidates(manifest, command, route, flag);
  const commandText = route.command || `rb ${command.domain} ${command.resource} ${route.verb}`;
  const filteredValues = values.filter((value) => {
    return typeof value === 'string' && (prefix.length === 0 || value.startsWith(prefix));
  });

  if (filteredValues.length > 0) {
    return filteredValues.map((value) => ({
      value,
      kind: 'flag-value',
      summary: `Value for --${flag.long}`,
      aliases: [],
      command: commandText
    }));
  }

  const placeholder = typeof flag.arg === 'string' && flag.arg.length > 0 ? flag.arg : flag.long.toUpperCase();
  return [
    {
      value: `<${placeholder}>`,
      kind: 'flag-value',
      summary: `Value for --${flag.long}`,
      aliases: [],
      command: commandText
    }
  ];
}

function resolveFlagValueCandidates(manifest, command, route, flag) {
  const candidates = [];
  const machineOutput = resolveMachineOutput(command, route);

  if (Array.isArray(flag.values)) {
    candidates.push(...flag.values);
  }

  const globalOption = (manifest.global_options || []).find((option) => {
    if (!option || typeof option.long !== 'string') {
      return false;
    }
    return option.long === flag.long || (flag.short && option.short === flag.short);
  });

  if (globalOption) {
    if (Array.isArray(globalOption.values)) {
      candidates.push(...globalOption.values);
    }
    if (typeof globalOption.value === 'string' && globalOption.value.length > 0) {
      candidates.push(globalOption.value);
    }
  }

  if (
    typeof machineOutput.preferred_flag === 'string' &&
    machineOutput.preferred_flag === flag.long &&
    typeof machineOutput.preferred_value === 'string' &&
    machineOutput.preferred_value.length > 0
  ) {
    candidates.push(machineOutput.preferred_value);
  }

  return Array.from(new Set(candidates.filter((value) => typeof value === 'string' && value.length > 0)));
}

function suggestRouteCommands(manifest = {}, selector, limit = 3) {
  const [domainToken = '', resourceToken = '', verbToken = ''] = normalizeRouteSelector(selector);
  const requested = `${domainToken}/${resourceToken}/${verbToken}`;
  const candidates = [];

  for (const domain of buildDomainCatalog(manifest)) {
    for (const resource of domain.resources || []) {
      for (const verb of resource.verbs || []) {
        const canonicalPath = `${domain.name}/${resource.name}/${verb.name}`;
        candidates.push({
          distance: levenshtein(requested, canonicalPath),
          command: `rb ${domain.name} ${resource.name} ${verb.name}`
        });
      }
    }
  }

  candidates.sort((a, b) => a.distance - b.distance || a.command.localeCompare(b.command));
  return candidates
    .filter((candidate) => candidate.distance <= 8)
    .slice(0, limit)
    .map((candidate) => candidate.command);
}

function matchesNodeToken(node, token) {
  if (!node || typeof token !== 'string') {
    return false;
  }

  if (typeof node.name === 'string' && node.name.startsWith(token)) {
    return true;
  }

  if (!Array.isArray(node.aliases)) {
    return false;
  }

  return node.aliases.some((alias) => typeof alias === 'string' && alias.startsWith(token));
}

function buildDomainCatalog(manifest = {}) {
  if (Array.isArray(manifest.domains) && manifest.domains.length > 0) {
    return manifest.domains;
  }

  const domains = new Map();

  for (const command of manifest.commands || []) {
    if (!domains.has(command.domain)) {
      domains.set(command.domain, {
        name: command.domain,
        aliases: Array.isArray(command.domain_aliases) ? command.domain_aliases.slice() : [],
        resources: []
      });
    }

    const domain = domains.get(command.domain);
    const resource = {
      name: command.resource,
      description: command.description || '',
      aliases: Array.isArray(command.resource_aliases) ? command.resource_aliases.slice() : [],
      verbs: (command.routes || []).map((route) => ({
        name: route.verb,
        summary: route.summary || '',
        aliases: Array.isArray(route.aliases) ? route.aliases.slice() : []
      }))
    };

    domain.resources.push(resource);
  }

  return Array.from(domains.values());
}

function createDomainProxy(binaryPath, manifest, defaults) {
  const client = {};

  for (const command of manifest.commands || []) {
    if (!client[command.domain]) {
      client[command.domain] = {};
    }
    if (!client[command.domain][command.resource]) {
      client[command.domain][command.resource] = {};
    }

    for (const route of command.routes || []) {
      attachRoute(client[command.domain][command.resource], binaryPath, command, route, defaults);
    }

    if (Array.isArray(command.resource_aliases)) {
      for (const alias of command.resource_aliases) {
        if (
          typeof alias === 'string' &&
          alias.length > 0 &&
          !client[command.domain][alias]
        ) {
          client[command.domain][alias] = client[command.domain][command.resource];
        }
      }
    }

    if (Array.isArray(command.domain_aliases)) {
      for (const alias of command.domain_aliases) {
        if (typeof alias === 'string' && alias.length > 0 && !client[alias]) {
          client[alias] = client[command.domain];
        }
      }
    }
  }

  return client;
}

async function createClient(options = {}) {
  const defaults = ensureObject(options, 'createClient options');
  const { binaryPath, manifest } = await getManifest(defaults);
  const api = createDomainProxy(binaryPath, manifest, defaults);
  const routeIndex = createRouteIndex(api);
  const domainCatalog = buildDomainCatalog(manifest);
  const commandCatalog = buildCommandCatalog(manifest);

  Object.defineProperties(api, {
    $binaryPath: {
      value: binaryPath,
      enumerable: false
    },
    $manifest: {
      value: manifest,
      enumerable: false
    },
    $routes: {
      value: routeIndex,
      enumerable: false
    },
    $domains: {
      value: domainCatalog,
      enumerable: false
    },
    $commands: {
      value: commandCatalog,
      enumerable: false
    },
    $findRoute: {
      value(selector) {
        return findRouteInvocation(routeIndex, manifest, selector);
      },
      enumerable: false
    },
    $suggest: {
      value(selector) {
        return suggestCommandTokens(manifest, selector);
      },
      enumerable: false
    },
    $complete: {
      value(selector) {
        return completeManifestTokens(manifest, selector);
      },
      enumerable: false
    },
    $describe: {
      value(selector) {
        return describeManifestRoute(manifest, selector);
      },
      enumerable: false
    },
    $help: {
      value(selector) {
        return formatRouteHelpSummary(manifest, selector);
      },
      enumerable: false
    },
    $downloadBinary: {
      value: downloadBinary,
      enumerable: false
    },
    $resolveBinary: {
      value: resolveBinary,
      enumerable: false
    },
    $exec: {
      value(args, execOptions = {}) {
        if (!Array.isArray(args)) {
          throw new TypeError('$exec expects an array of CLI arguments');
        }
        return execFilePromise(binaryPath, args, Object.assign({}, defaults, execOptions));
      },
      enumerable: false
    },
    $spawn: {
      value(args, spawnOptions = {}) {
        if (!Array.isArray(args)) {
          throw new TypeError('$spawn expects an array of CLI arguments');
        }
        return spawnBinary(binaryPath, args, Object.assign({}, defaults, spawnOptions));
      },
      enumerable: false
    }
  });

  return api;
}

module.exports = {
  version: SDK_VERSION,
  checkForUpdates,
  createClient,
  downloadBinary,
  ensureInstalled,
  getBinaryInfo,
  getManifest,
  getInstalledVersion,
  runCli,
  runJson,
  resolveAssetName,
  resolveBinary,
  upgradeBinary
};

module.exports._internal = {
  attachRoute,
  buildDomainCatalog,
  buildCommandCatalog,
  buildInvocation,
  checkForUpdates,
  createDomainProxy,
  createRouteIndex,
  defaultInstallDir,
  downloadToFile,
  ensureInstalled,
  ensureObject,
  execFilePromise,
  exists,
  formatManifestHelpSummary,
  formatPartialRouteHelp,
  formatRouteHelpSummary,
  formatSdkHelpOutput,
  formatUnknownRouteHelp,
  formatWrapperBinaryStatus,
  formatWrapperHelp,
  findFlag,
  getBinaryInfo,
  getDefaultBinaryName,
  getInstalledVersion,
  getReleaseTag,
  hasLongFlag,
  buildJsonCliArgs,
  invokeJson,
  invokeRaw,
  isExecutable,
  kebabToCamel,
  legacyInstallDir,
  normalizeReleaseTag,
  normalizeCliArgv,
  normalizeSdkHelpSelector,
  normalizeTokenSelector,
  normalizeRouteSelector,
  globalOptionExpectsValue,
  buildGlobalOptionIndex,
  extractRouteSelectorFromArgv,
  findCommandStartIndex,
  resolveCanonicalRouteTokens,
  parseWrapperArgs,
  parseInstalledVersion,
  request,
  requestJson,
  requestText,
  aliasIncludes,
  findRouteInvocation,
  describeManifestRoute,
  completeManifestTokens,
  looksLikeCanonicalCommandArgs,
  routeInvocationMeta,
  resolveMachineOutput,
  routeIdentifier,
  runJson,
  suggestCommandTokens,
  suggestRouteCommands,
  resolveFromPath,
  resolveBinaryWithInfo,
  resolveLegacyBinaryPath,
  resolvePackageLocalBinaryPath,
  resolveManagedBinaryPath,
  resolveManagedUpgradeDestination,
  sha256File,
  splitWrapperArgs,
  spawnBinary,
  profileArgs,
  upgradeBinary,
  waitForChild,
  writeLine,
  verifyChecksum
};

module.exports.default = module.exports;

/* node:coverage disable */
if (require.main === module) {
  runCli().then((code) => {
    process.exitCode = code;
  });
}
/* node:coverage enable */

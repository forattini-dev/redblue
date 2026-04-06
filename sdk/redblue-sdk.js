#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const https = require('https');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const { execFile, spawn } = require('child_process');

const DEFAULT_REPO = 'forattini-dev/redblue';
const LOCAL_CLI_ARGS_PARSER_PATH = path.resolve(
  __dirname,
  '../../../tetis/libs/cli-args-parser/dist/index.js'
);
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
const WRAPPER_OPTION_SCHEMA = Object.freeze({
  options: {
    'asset-name': {
      type: 'string'
    },
    'auto-download': {
      type: 'boolean',
      aliases: ['download']
    },
    'binary-path': {
      type: 'string'
    },
    channel: {
      type: 'string'
    },
    'check-update': {
      type: 'boolean'
    },
    'github-token': {
      type: 'string'
    },
    force: {
      type: 'boolean'
    },
    install: {
      type: 'boolean'
    },
    repo: {
      type: 'string'
    },
    'print-binary-path': {
      type: 'boolean'
    },
    'release-version': {
      type: 'string',
      aliases: ['version']
    },
    'sdk-help': {
      type: 'boolean'
    },
    'static-build': {
      type: 'boolean'
    },
    'target-dir': {
      type: 'string'
    },
    upgrade: {
      type: 'boolean'
    },
    verify: {
      type: 'boolean'
    }
  }
});

function getDefaultBinaryName(platform = process.platform) {
  return platform === 'win32' ? 'rb.exe' : 'rb';
}

const DEFAULT_BINARY_NAME = getDefaultBinaryName();

function kebabToCamel(value) {
  return String(value).replace(/[-_]+([a-zA-Z0-9])/g, (_, ch) => ch.toUpperCase());
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

function resolveFromPath(binaryName) {
  const pathValue = process.env.PATH || '';
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

function defaultInstallDir() {
  return process.env.REDBLUE_INSTALL_DIR || process.env.INSTALL_DIR || path.join(os.homedir(), '.local', 'bin');
}

function legacyInstallDir() {
  return path.join(os.homedir(), '.redblue', 'bin');
}

function resolveManagedBinaryPath(options = {}) {
  if (options.binaryPath) {
    return path.resolve(options.binaryPath);
  }

  const installDir = options.targetDir || defaultInstallDir();
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

  const pathCandidate = resolveFromPath(binaryName);
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

function execFilePromise(binaryPath, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      binaryPath,
      args,
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
  return spawn(binaryPath, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: options.stdio || 'inherit',
    detached: options.detached === true
  });
}

function toImportSpecifier(filePath) {
  return pathToFileURL(path.resolve(filePath)).href;
}

function getParserCandidatePaths(runtime = {}) {
  const env = runtime.env || process.env;
  const localParserPath = runtime.localParserPath || LOCAL_CLI_ARGS_PARSER_PATH;
  const candidates = [];
  const seen = new Set();

  function pushCandidate(specifier) {
    if (!specifier || seen.has(specifier)) {
      return;
    }
    seen.add(specifier);
    candidates.push(specifier);
  }

  if (env.REDBLUE_CLI_ARGS_PARSER_PATH) {
    pushCandidate(toImportSpecifier(env.REDBLUE_CLI_ARGS_PARSER_PATH));
  }

  pushCandidate('cli-args-parser');

  if (localParserPath && exists(localParserPath)) {
    pushCandidate(toImportSpecifier(localParserPath));
  }

  return candidates;
}

async function loadCliArgsParser(runtime = {}) {
  if (runtime.parserModule) {
    return runtime.parserModule;
  }

  const importModule =
    runtime.importModule ||
    (async function defaultImport(specifier) {
      return import(specifier);
    });

  const candidates = Array.isArray(runtime.parserCandidates)
    ? runtime.parserCandidates.slice()
    : getParserCandidatePaths(runtime);
  const failures = [];

  for (const specifier of candidates) {
    try {
      return await importModule(specifier);
    } catch (error) {
      failures.push(`${specifier}: ${error.message}`);
    }
  }

  /* node:coverage disable */
  const failureSummary = failures.length > 0 ? failures.join('; ') : 'no candidates available';
  /* node:coverage enable */
  throw new Error(`Unable to load cli-args-parser. Tried: ${failureSummary}`);
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
  const rawArgs = Array.isArray(argv) ? argv.slice() : [];
  const parserModule = await loadCliArgsParser(runtime);
  const { createParser } = parserModule;

  if (typeof createParser !== 'function') {
    throw new Error('cli-args-parser does not export createParser');
  }

  const split = splitWrapperArgs(rawArgs);
  const parser = createParser(WRAPPER_OPTION_SCHEMA);
  const parsed = parser.parse(split.wrapperArgs);

  if (Array.isArray(parsed.errors) && parsed.errors.length > 0) {
    throw new Error(parsed.errors.join('; '));
  }

  const options = parsed.options || {};
  const releaseVersion = options['release-version'] || options.version;

  return {
    passthroughArgs: split.passthroughArgs,
    rawArgs,
    resolveOptions: {
      assetName: options['asset-name'],
      autoDownload: options['auto-download'] === true || options.download === true,
      binaryPath: options['binary-path'],
      channel: options.channel,
      force: options.force === true,
      githubToken: options['github-token'],
      repo: options.repo,
      releaseVersion,
      staticBuild: options['static-build'] === true,
      targetDir: options['target-dir'],
      verify: options.verify !== false,
      version: releaseVersion
    },
    usedDoubleDash: split.usedDoubleDash,
    wrapperOptions: {
      checkUpdate: options['check-update'] === true,
      install: options.install === true,
      printBinaryPath: options['print-binary-path'] === true,
      sdkHelp: options['sdk-help'] === true,
      upgrade: options.upgrade === true
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

function formatWrapperHelp() {
  return [
    'redblue-cli wrapper',
    '',
    'Usage:',
    '  rb [wrapper options] [redblue args]',
    '  npx redblue-cli [redblue args]',
    '  npm exec --package redblue-cli rb -- [redblue args]',
    '',
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
    '  When installed from npm, the package postinstall step stores the managed binary in package-local .redblue/bin and the wrapper can use it automatically.',
    '  Use "rb --version" to query the real redblue binary version after installation.',
    '  The exact command "npx rb" only works when a package named "rb" exists or when this package is already installed and exposes the rb bin.',
    ''
  ].join('\n');
}

function waitForChild(child) {
  return new Promise((resolve, reject) => {
    child.on('error', reject);
    /* node:coverage disable */
    child.on('close', (code, signal) => {
      if (signal) {
        resolve(1);
        return;
      }
      resolve(typeof code === 'number' ? code : 1);
    });
    /* node:coverage enable */
  });
}

async function runCli(argv = process.argv.slice(2), runtime = {}) {
  const stdout = runtime.stdout || process.stdout;
  const stderr = runtime.stderr || process.stderr;

  try {
    const parsed = await parseWrapperArgs(argv, runtime);
    const cliOptions = Object.assign({}, parsed.resolveOptions, {
      cwd: runtime.cwd || process.cwd(),
      env: Object.assign({}, process.env, runtime.env || {})
    });

    if (parsed.wrapperOptions.sdkHelp) {
      writeLine(stdout, formatWrapperHelp());
      return 0;
    }

    let resolvedInfo = null;

    if (parsed.wrapperOptions.checkUpdate) {
      const updateStatus = await checkForUpdates(cliOptions);
      const updateMessage = formatWrapperBinaryStatus(updateStatus);

      if (parsed.passthroughArgs.length === 0) {
        writeLine(stdout, updateMessage);
        return 0;
      }

      writeLine(stderr, updateMessage);
    }

    if (parsed.wrapperOptions.upgrade) {
      const upgradeResult = await upgradeBinary(cliOptions);
      resolvedInfo = {
        binaryPath: upgradeResult.binaryPath,
        source: upgradeResult.source
      };

      if (parsed.passthroughArgs.length === 0 && !parsed.wrapperOptions.printBinaryPath) {
        writeLine(stdout, formatWrapperBinaryStatus(upgradeResult));
        return 0;
      }

      writeLine(stderr, formatWrapperBinaryStatus(upgradeResult));
    } else if (parsed.wrapperOptions.install) {
      const installResult = await ensureInstalled(cliOptions);
      resolvedInfo = {
        binaryPath: installResult.binaryPath,
        source: installResult.source
      };

      if (parsed.passthroughArgs.length === 0 && !parsed.wrapperOptions.printBinaryPath) {
        writeLine(stdout, formatWrapperBinaryStatus(installResult));
        return 0;
      }

      writeLine(stderr, formatWrapperBinaryStatus(installResult));
    }

    if (!resolvedInfo) {
      resolvedInfo = await resolveBinaryWithInfo(cliOptions);
    }

    if (parsed.wrapperOptions.printBinaryPath) {
      if (parsed.passthroughArgs.length === 0) {
        writeLine(stdout, resolvedInfo.binaryPath);
        return 0;
      }
      writeLine(stderr, `redblue binary: ${resolvedInfo.binaryPath}`);
    }

    const binaryPath = resolvedInfo.binaryPath;
    /* node:coverage disable */
    const spawnOptions = {
      cwd: runtime.cwd || process.cwd(),
      env: Object.assign({}, process.env, runtime.env || {}),
      stdio: runtime.stdio || 'inherit'
    };
    /* node:coverage enable */
    const child = spawnBinary(binaryPath, parsed.passthroughArgs, spawnOptions);

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

function buildInvocation(command, route, input, execOptions) {
  const payload = ensureObject(input, 'route input');
  const args = [command.domain, command.resource, route.verb];
  const consumedKeys = new Set();
  const positionals = Array.isArray(route.positionals) ? route.positionals : [];
  const flags = Array.isArray(command.flags) ? command.flags : [];
  const extraFlags = ensureObject(payload.flags, 'flags');
  const preferredFlag =
    command.machine_output && typeof command.machine_output.preferred_flag === 'string'
      ? command.machine_output.preferred_flag
      : null;
  const preferredValue =
    command.machine_output && typeof command.machine_output.preferred_value === 'string'
      ? command.machine_output.preferred_value
      : 'json';

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
          `Missing required positional "${positional.name}" for ${command.domain} ${command.resource} ${route.verb}`
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
        `Unknown flag "${key}" for ${command.domain} ${command.resource} ${route.verb}`
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
        `Unknown parameter "${key}" for ${command.domain} ${command.resource} ${route.verb}`
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
      `redblue command did not emit valid JSON for ${command.domain} ${command.resource} ${route.verb}: ${error.message}`
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
  }

  return client;
}

async function createClient(options = {}) {
  const defaults = ensureObject(options, 'createClient options');
  const { binaryPath, manifest } = await getManifest(defaults);
  const api = createDomainProxy(binaryPath, manifest, defaults);

  Object.defineProperties(api, {
    $binaryPath: {
      value: binaryPath,
      enumerable: false
    },
    $manifest: {
      value: manifest,
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
  checkForUpdates,
  createClient,
  downloadBinary,
  ensureInstalled,
  getBinaryInfo,
  getManifest,
  getInstalledVersion,
  runCli,
  resolveAssetName,
  resolveBinary,
  upgradeBinary
};

module.exports._internal = {
  attachRoute,
  buildInvocation,
  checkForUpdates,
  createDomainProxy,
  defaultInstallDir,
  downloadToFile,
  ensureInstalled,
  ensureObject,
  execFilePromise,
  exists,
  formatWrapperBinaryStatus,
  formatWrapperHelp,
  findFlag,
  getBinaryInfo,
  getParserCandidatePaths,
  getDefaultBinaryName,
  getInstalledVersion,
  getReleaseTag,
  invokeJson,
  invokeRaw,
  isExecutable,
  kebabToCamel,
  legacyInstallDir,
  loadCliArgsParser,
  normalizeReleaseTag,
  parseWrapperArgs,
  parseInstalledVersion,
  request,
  requestJson,
  requestText,
  resolveFromPath,
  resolveBinaryWithInfo,
  resolveLegacyBinaryPath,
  resolvePackageLocalBinaryPath,
  resolveManagedBinaryPath,
  resolveManagedUpgradeDestination,
  sha256File,
  splitWrapperArgs,
  spawnBinary,
  toImportSpecifier,
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

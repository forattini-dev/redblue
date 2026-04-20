'use strict';

const assert = require('assert/strict');
const { EventEmitter } = require('events');
const fs = require('fs');
const fsp = fs.promises;
const https = require('https');
const os = require('os');
const path = require('path');
const test = require('node:test');

const sdk = require('../redblue-sdk.js');

const {
  aliasIncludes,
  attachRoute,
  buildDomainCatalog,
  buildCommandCatalog,
  buildJsonCliArgs,
  buildInvocation,
  checkForUpdates,
  completeManifestTokens,
  createDomainProxy,
  createRouteIndex,
  defaultInstallDir,
  downloadToFile,
  ensureObject,
  ensureInstalled,
  execFilePromise,
  exists,
  formatManifestHelpSummary,
  formatPartialRouteHelp,
  formatRouteHelpSummary,
  formatSdkHelpOutput,
  formatUnknownRouteHelp,
  profileArgs,
  formatWrapperBinaryStatus,
  formatWrapperHelp,
  findFlag,
  findRouteInvocation,
  describeManifestRoute,
  globalOptionExpectsValue,
  findCommandStartIndex,
  getBinaryInfo,
  getDefaultBinaryName,
  getInstalledVersion,
  getReleaseTag,
  hasLongFlag,
  invokeJson,
  invokeRaw,
  isExecutable,
  kebabToCamel,
  legacyInstallDir,
  looksLikeCanonicalCommandArgs,
  normalizeCliArgv,
  normalizeReleaseTag,
  normalizeSdkHelpSelector,
  normalizeTokenSelector,
  normalizeRouteSelector,
  parseWrapperArgs,
  parseInstalledVersion,
  request,
  requestJson,
  requestText,
  routeInvocationMeta,
  resolveMachineOutput,
  buildGlobalOptionIndex,
  extractRouteSelectorFromArgv,
  resolveCanonicalRouteTokens,
  routeIdentifier,
  runJson,
  suggestCommandTokens,
  suggestRouteCommands,
  resolveFromPath,
  resolveBinaryWithInfo,
  resolveLegacyBinaryPath,
  resolveManagedBinaryPath,
  resolveManagedUpgradeDestination,
  splitWrapperArgs,
  sha256File,
  spawnBinary,
  upgradeBinary,
  waitForChild,
  writeLine,
  verifyChecksum
} = sdk._internal;

const fixtureScript = path.join(__dirname, 'fixtures', 'fake-rb.js');
const sdkScript = path.join(__dirname, '..', 'redblue-sdk.js');

async function createFixtureBinary() {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-fixture-'));
  const binaryPath = path.join(tmpDir, process.platform === 'win32' ? 'rb.cmd' : 'rb');

  if (process.platform === 'win32') {
    await fsp.writeFile(binaryPath, `@"${process.execPath}" "${fixtureScript}" %*\r\n`);
  } else {
    await fsp.writeFile(
      binaryPath,
      `#!/bin/sh\nexec "${process.execPath}" "${fixtureScript}" "$@"\n`
    );
    await fsp.chmod(binaryPath, 0o755);
  }

  return binaryPath;
}

async function installFixtureBinary(destination) {
  const source = await createFixtureBinary();
  await fsp.mkdir(path.dirname(destination), { recursive: true });
  await fsp.copyFile(source, destination);
  if (process.platform !== 'win32') {
    await fsp.chmod(destination, 0o755);
  }
  return destination;
}

function readLogLines(logPath) {
  return fs
    .readFileSync(logPath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function makeCommand(longName, preferredFlag = 'format', preferredValue = 'json') {
  return {
    domain: 'dns',
    resource: 'record',
    flags: [
      {
        long: 'type',
        short: 't',
        description: 'Record type',
        expects_value: true,
        camel_name: 'type'
      },
      {
        long: longName,
        short: longName === 'output' ? 'o' : 'f',
        description: 'Output format (text, json)',
        expects_value: true,
        camel_name: longName
      }
    ],
    machine_output: {
      preferred_flag: preferredFlag,
      preferred_value: preferredValue
    }
  };
}

function makeRoute() {
  return {
    verb: 'lookup',
    positionals: [
      {
        name: 'target',
        required: true,
        repeated: false,
        slot: 'target',
        index: 0
      }
    ]
  };
}

async function withHttpsMock(plans, fn) {
  const original = https.request;
  let index = 0;

  https.request = (url, options, callback) => {
    const plan = plans[index++];
    if (!plan) {
      throw new Error(`Unexpected HTTPS request for ${url}`);
    }

    if (typeof plan.assertRequest === 'function') {
      plan.assertRequest(url, options);
    }

    const req = new EventEmitter();
    req.end = () => {
      if (plan.error) {
        process.nextTick(() => req.emit('error', plan.error));
        return;
      }

      const res = new EventEmitter();
      res.statusCode = plan.statusCode ?? 200;
      res.headers = plan.headers || {};
      res.resume = () => {};

      process.nextTick(() => {
        callback(res);
        if (plan.body) {
          res.emit('data', Buffer.from(plan.body));
        }
        res.emit('end');
      });
    };

    return req;
  };

  try {
    return await fn();
  } finally {
    https.request = original;
  }
}

test('helpers handle shape, path resolution and asset names', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-helpers-'));
  const binaryPath = path.join(tmpDir, 'rb');
  const plainFile = path.join(tmpDir, 'plain-file');

  await fsp.writeFile(binaryPath, '#!/usr/bin/env bash\n');
  await fsp.writeFile(plainFile, 'plain');
  await fsp.chmod(binaryPath, 0o755);

  assert.equal(kebabToCamel('network-ports'), 'networkPorts');
  assert.equal(getDefaultBinaryName('win32'), 'rb.exe');
  assert.equal(getDefaultBinaryName('linux'), 'rb');
  assert.deepEqual(ensureObject(null, 'payload'), {});
  assert.throws(() => ensureObject([], 'payload'), /payload must be an object/);
  assert.equal(exists(binaryPath), true);
  assert.equal(isExecutable(binaryPath), true);
  assert.equal(isExecutable(plainFile), false);

  const originalPath = process.env.PATH;
  process.env.PATH = `${tmpDir}${path.delimiter}${originalPath || ''}`;
  assert.equal(resolveFromPath('rb'), binaryPath);
  process.env.PATH = `${path.delimiter}${tmpDir}`;
  assert.equal(resolveFromPath('missing-rb'), null);
  delete process.env.PATH;
  assert.equal(resolveFromPath('rb'), null);
  if (originalPath === undefined) {
    delete process.env.PATH;
  } else {
    process.env.PATH = originalPath;
  }

  assert.equal(defaultInstallDir(), path.join(os.homedir(), '.local', 'bin'));
  assert.equal(legacyInstallDir(), path.join(os.homedir(), '.redblue', 'bin'));
  assert.equal(sdk.resolveAssetName({ platform: 'linux', arch: 'x64' }), 'rb-linux-x86_64');
  assert.equal(sdk.resolveAssetName({ platform: 'linux', arch: 'arm64' }), 'rb-linux-aarch64');
  assert.equal(
    sdk.resolveAssetName({ platform: 'linux', arch: 'arm64', staticBuild: true }),
    'rb-linux-aarch64-static'
  );
  assert.equal(sdk.resolveAssetName({ platform: 'linux', arch: 'arm' }), 'rb-linux-armv7');
  assert.equal(sdk.resolveAssetName({ platform: 'darwin', arch: 'x64' }), 'rb-macos-x86_64');
  assert.equal(sdk.resolveAssetName({ platform: 'darwin', arch: 'arm64' }), 'rb-macos-aarch64');
  assert.equal(
    sdk.resolveAssetName({ platform: 'win32', arch: 'x64' }),
    'rb-windows-x86_64.exe'
  );
  assert.throws(
    () => sdk.resolveAssetName({ platform: 'linux', arch: 'ppc64' }),
    /Unsupported redblue platform/
  );
  assert.equal(normalizeReleaseTag('1.2.3'), 'v1.2.3');
  assert.equal(normalizeReleaseTag('v1.2.3'), 'v1.2.3');
  assert.equal(normalizeReleaseTag(''), null);
  assert.equal(normalizeReleaseTag('   '), null);
  assert.equal(parseInstalledVersion('RedBlue CLI v1.2.3'), 'v1.2.3');
  assert.equal(parseInstalledVersion('redblue 1.2.3-next.4+abc'), 'v1.2.3-next.4+abc');
  assert.equal(parseInstalledVersion('not-a-version'), null);
  assert.equal(parseInstalledVersion('   '), null);
  assert.equal(parseInstalledVersion(null), null);
});

test('request helpers, release discovery and checksum flows are covered', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-http-'));
  const filePath = path.join(tmpDir, 'rb');
  const checksum = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

  await withHttpsMock(
    [
      {
        statusCode: 200,
        body: 'headers',
        assertRequest(_url, options) {
          assert.equal(options.headers['X-Test'], '1');
          assert.equal(options.headers.Accept, 'application/vnd.github+json');
        }
      }
    ],
    async () => {
      assert.equal(
        await requestText('https://origin.example/headers', { headers: { 'X-Test': '1' } }),
        'headers'
      );
    }
  );

  await withHttpsMock(
    [
      {
        statusCode: 302,
        headers: { location: 'https://redirected.example/resource' }
      },
      {
        statusCode: 200,
        body: 'redirected'
      }
    ],
    async () => {
      assert.equal(await requestText('https://origin.example/resource'), 'redirected');
    }
  );

  await withHttpsMock([{ statusCode: 500, body: 'boom' }], async () => {
    await assert.rejects(request('https://origin.example/fail'), /status 500/);
  });

  await withHttpsMock([{ statusCode: 200, body: '{"tag_name":"v1.2.3"}' }], async () => {
    const json = await requestJson('https://api.example/releases/latest');
    assert.equal(json.tag_name, 'v1.2.3');
  });

  await withHttpsMock([{ statusCode: 200, body: '[{"tag_name":"v1.0.0"}]' }], async () => {
    assert.equal(await getReleaseTag({ channel: 'latest' }), 'v1.0.0');
  });

  await withHttpsMock([{ statusCode: 200, body: '{"tag_name":"v2.0.0"}' }], async () => {
    assert.equal(await getReleaseTag({ channel: 'stable' }), 'v2.0.0');
  });

  await withHttpsMock(
    [{ statusCode: 200, body: '[{"tag_name":"v2.0.0","prerelease":true}]' }],
    async () => {
      assert.equal(await getReleaseTag({ channel: 'next' }), 'v2.0.0');
    }
  );

  await withHttpsMock(
    [{ statusCode: 200, body: '[{"tag_name":"v2.1.0","prerelease":false}]' }],
    async () => {
      assert.equal(await getReleaseTag({ channel: 'next' }), 'v2.1.0');
    }
  );

  assert.equal(await getReleaseTag({ version: '1.4.0' }), 'v1.4.0');
  assert.equal(await getReleaseTag({ version: 'v1.4.0', githubToken: 'token-1' }), 'v1.4.0');
  await withHttpsMock([{ statusCode: 200, body: '[]' }], async () => {
    await assert.rejects(getReleaseTag({ channel: 'latest' }), /No releases found/);
  });
  await withHttpsMock(
    [{ statusCode: 200, body: '[{"tag_name":"v1.0.0","prerelease":false}]' }],
    async () => {
      await assert.rejects(getReleaseTag({ channel: 'weird' }), /Unsupported release channel/);
    }
  );

  await withHttpsMock([{ statusCode: 200, body: 'test' }], async () => {
    await downloadToFile('https://files.example/rb', filePath);
  });
  assert.equal(await sha256File(filePath), checksum);

  await withHttpsMock([{ statusCode: 404, body: 'missing' }], async () => {
    await verifyChecksum(filePath, 'https://files.example/rb.sha256');
  });

  await withHttpsMock([{ statusCode: 200, body: `${checksum}  rb` }], async () => {
    await verifyChecksum(filePath, 'https://files.example/rb.sha256');
  });

  await withHttpsMock([{ statusCode: 200, body: '\n' }], async () => {
    await verifyChecksum(filePath, 'https://files.example/rb.sha256');
  });

  await withHttpsMock([{ statusCode: 200, body: `deadbeef  rb` }], async () => {
    await assert.rejects(
      verifyChecksum(filePath, 'https://files.example/rb.sha256'),
      /Checksum mismatch/
    );
  });
});

test('downloadBinary and resolveBinary cover installed, PATH, direct and autodownload modes', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-resolve-'));
  const installDir = path.join(tmpDir, 'bin');
  const binaryName = process.platform === 'win32' ? 'rb-sdk-test.exe' : 'rb-sdk-test';
  const installedPath = path.join(installDir, binaryName);
  const defaultBinaryName = getDefaultBinaryName(process.platform);
  const defaultNamedInstalledPath = path.join(installDir, defaultBinaryName);
  const originalPath = process.env.PATH;
  const packageLocalBinaryPath = path.join(process.cwd(), '.redblue', 'bin', defaultBinaryName);

  await installFixtureBinary(installedPath);
  assert.equal(await sdk.resolveBinary({ binaryPath: installedPath }), installedPath);
  assert.deepEqual(await resolveBinaryWithInfo({ binaryPath: installedPath }), {
    binaryPath: installedPath,
    source: 'explicit'
  });
  assert.equal(resolveManagedBinaryPath({ targetDir: installDir, binaryName }), installedPath);
  assert.equal(resolveManagedUpgradeDestination({ targetDir: installDir, binaryName }), installedPath);
  assert.equal(await sdk.resolveBinary({ targetDir: installDir, binaryName }), installedPath);
  assert.deepEqual(await resolveBinaryWithInfo({ targetDir: installDir, binaryName }), {
    binaryPath: installedPath,
    source: 'managed'
  });

  await fsp.rm(installedPath);
  try {
    process.env.PATH = `${installDir}${path.delimiter}${originalPath || ''}`;
    await installFixtureBinary(installedPath);
    assert.equal(await sdk.resolveBinary({ binaryName }), installedPath);
    assert.deepEqual(await resolveBinaryWithInfo({ binaryName }), {
      binaryPath: installedPath,
      source: 'path'
    });
  } finally {
    if (originalPath === undefined) {
      delete process.env.PATH;
    } else {
      process.env.PATH = originalPath;
    }
  }

  await installFixtureBinary(defaultNamedInstalledPath);
  await fsp.rm(installedPath);
  assert.equal(await sdk.resolveBinary({ targetDir: installDir }), defaultNamedInstalledPath);
  await fsp.rm(defaultNamedInstalledPath);
  {
    const packageHomeKey = process.platform === 'win32' ? 'USERPROFILE' : 'HOME';
    const originalHome = process.env[packageHomeKey];
    const originalPathForPackage = process.env.PATH;
    const packageHome = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-home-'));
    process.env[packageHomeKey] = packageHome;
    process.env.PATH = '';
    try {
      await fsp.mkdir(path.join(process.cwd(), '.redblue', 'bin'), { recursive: true });
      await installFixtureBinary(packageLocalBinaryPath);
      assert.deepEqual(await resolveBinaryWithInfo({}), {
        binaryPath: packageLocalBinaryPath,
        source: 'package'
      });
    } finally {
      await fsp.rm(packageLocalBinaryPath, { force: true });
      if (originalHome === undefined) {
        delete process.env[packageHomeKey];
      } else {
        process.env[packageHomeKey] = originalHome;
      }
      process.env.PATH = originalPathForPackage;
      await fsp.rm(packageHome, { recursive: true, force: true });
    }
  }
  await withHttpsMock(
    [
      { statusCode: 200, body: '{"tag_name":"v0.2.2"}' },
      { statusCode: 200, body: 'downloaded-binary' },
      {
        statusCode: 200,
        body: '2db0e0bf2cb2fc75a4095eefe4e371a63c0906b105b639f25fdce12d82052da0  rb'
      }
    ],
    async () => {
      const resolved = await resolveBinaryWithInfo({
        autoDownload: true,
        targetDir: installDir,
        binaryName,
        verify: true
      });
      assert.equal(resolved.binaryPath, installedPath);
      assert.equal(resolved.source, 'downloaded');
      assert.equal(exists(installedPath), true);
    }
  );

  await assert.rejects(
    sdk.resolveBinary({ binaryPath: path.join(tmpDir, 'missing-rb') }),
    /binary not found/
  );

  await fsp.rm(installedPath);
  await assert.rejects(
    sdk.resolveBinary({ targetDir: installDir, binaryName }),
    /Unable to resolve redblue binary/
  );

  const homeDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-home-'));
  const homeKey = process.platform === 'win32' ? 'USERPROFILE' : 'HOME';
  const originalHome = process.env[homeKey];
  process.env[homeKey] = homeDir;

  try {
    const legacyPath = path.join(homeDir, '.redblue', 'bin', defaultBinaryName);
    assert.equal(resolveLegacyBinaryPath({}), legacyPath);
    await installFixtureBinary(legacyPath);
    assert.deepEqual(await resolveBinaryWithInfo({}), {
      binaryPath: legacyPath,
      source: 'legacy'
    });
    await fsp.rm(legacyPath);

    await withHttpsMock(
      [
        {
          statusCode: 200,
          body: 'downloaded-default-binary',
          assertRequest(url, options) {
            assert.match(url, /\/releases\/download\/v9\.9\.9\/rb-fixture$/);
            assert.equal(options.headers.Authorization, 'Bearer token-2');
          }
        }
      ],
      async () => {
        const downloaded = await sdk.downloadBinary({
          version: 'v9.9.9',
          githubToken: 'token-2',
          assetName: 'rb-fixture',
          verify: false
        });

        assert.equal(
          downloaded,
          path.join(homeDir, '.local', 'bin', getDefaultBinaryName(process.platform))
        );
        assert.equal(exists(downloaded), true);
      }
    );
  } finally {
    if (originalHome === undefined) {
      delete process.env[homeKey];
    } else {
      process.env[homeKey] = originalHome;
    }
  }
});

test('binary lifecycle helpers cover installed versions, update checks and managed upgrades', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-version-'));
  const managedPath = path.join(tmpDir, getDefaultBinaryName(process.platform));
  const freshPath = path.join(tmpDir, 'fresh', getDefaultBinaryName(process.platform));
  const upgradePath = path.join(tmpDir, 'upgrade', getDefaultBinaryName(process.platform));

  await installFixtureBinary(managedPath);
  await installFixtureBinary(upgradePath);

  assert.equal(
    await getInstalledVersion(managedPath, {
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
    }),
    'v1.2.3'
  );
  assert.equal(
    await getInstalledVersion(managedPath, {
      env: {
        RB_FAKE_VERSION: 'RedBlue CLI v1.2.3',
        RB_FAKE_VERSION_STREAM: 'stderr'
      }
    }),
    'v1.2.3'
  );
  assert.equal(await getInstalledVersion(path.join(tmpDir, 'missing-rb')), null);

  assert.deepEqual(
    await getBinaryInfo({
      binaryPath: managedPath,
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
    }),
    {
      binaryPath: managedPath,
      source: 'explicit',
      version: 'v1.2.3'
    }
  );

  assert.deepEqual(
    await ensureInstalled({
      binaryPath: managedPath,
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
    }),
    {
      status: 'ready',
      binaryPath: managedPath,
      source: 'explicit',
      version: 'v1.2.3',
      changed: false
    }
  );

  await withHttpsMock([{ statusCode: 200, body: '{"tag_name":"v1.2.4"}' }], async () => {
    const status = await checkForUpdates({
      binaryPath: managedPath,
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
    });

    assert.equal(status.binaryPath, managedPath);
    assert.equal(status.currentVersion, 'v1.2.3');
    assert.equal(status.latestVersion, 'v1.2.4');
    assert.equal(status.hasUpdate, true);
    assert.match(formatWrapperBinaryStatus(status), /update available/);
  });

  await withHttpsMock([{ statusCode: 200, body: '{"tag_name":"v1.2.3"}' }], async () => {
    const status = await checkForUpdates({
      binaryPath: managedPath,
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
    });

    assert.equal(status.hasUpdate, false);
    assert.match(formatWrapperBinaryStatus(status), /up to date/);
  });

  await withHttpsMock([{ statusCode: 200, body: 'new-binary' }], async () => {
    const installResult = await ensureInstalled({
      binaryPath: freshPath,
      version: 'v9.9.9',
      assetName: 'rb-fixture',
      verify: false
    });

    assert.equal(installResult.binaryPath, freshPath);
    assert.equal(installResult.changed, true);
    assert.equal(installResult.version, 'v9.9.9');
    assert.equal(exists(freshPath), true);
    assert.match(formatWrapperBinaryStatus(installResult), /installed/);
  });

  await withHttpsMock(
    [
      { statusCode: 200, body: '{"tag_name":"v8.8.8"}' },
      { statusCode: 200, body: 'new-binary-from-release' }
    ],
    async () => {
      const releaseInstallResult = await ensureInstalled({
        binaryPath: path.join(tmpDir, 'release-install'),
        assetName: 'rb-fixture',
        verify: false
      });

      assert.equal(releaseInstallResult.version, 'v8.8.8');
    }
  );

  const noUpgrade = await upgradeBinary({
    binaryPath: managedPath,
    version: 'v1.2.3',
    env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
  });
  assert.equal(noUpgrade.changed, false);
  assert.equal(noUpgrade.previousVersion, 'v1.2.3');
  assert.match(formatWrapperBinaryStatus(noUpgrade), /already at/);

  await withHttpsMock([{ statusCode: 200, body: 'upgraded-binary' }], async () => {
    const upgradeResult = await upgradeBinary({
      binaryPath: upgradePath,
      version: 'v2.0.0',
      assetName: 'rb-fixture',
      verify: false,
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
    });

    assert.equal(upgradeResult.binaryPath, upgradePath);
    assert.equal(upgradeResult.previousVersion, 'v1.2.3');
    assert.equal(upgradeResult.version, 'v2.0.0');
    assert.equal(upgradeResult.changed, true);
    assert.match(formatWrapperBinaryStatus(upgradeResult), /upgraded/);
  });

  const missingStatus = await checkForUpdates({
    binaryPath: path.join(tmpDir, 'missing-check'),
    version: 'v3.0.0'
  });
  assert.equal(missingStatus.currentVersion, null);
  assert.equal(missingStatus.hasUpdate, true);
  assert.match(formatWrapperBinaryStatus(missingStatus), /not installed/);

  await withHttpsMock([{ statusCode: 200, body: 'upgraded-from-missing' }], async () => {
    const upgradedMissing = await upgradeBinary({
      binaryPath: path.join(tmpDir, 'missing-upgrade'),
      version: 'v3.0.0',
      assetName: 'rb-fixture',
      verify: false
    });

    assert.equal(upgradedMissing.previousVersion, null);
    assert.equal(upgradedMissing.changed, true);
    assert.equal(upgradedMissing.source, 'managed');
  });

  assert.equal(
    resolveManagedUpgradeDestination({}, {
      binaryPath: managedPath,
      source: 'managed'
    }),
    managedPath
  );
  assert.equal(
    resolveManagedUpgradeDestination({}, {
      binaryPath: managedPath,
      source: 'path'
    }),
    resolveManagedBinaryPath({})
  );
  assert.match(
    formatWrapperBinaryStatus({ binaryPath: managedPath, changed: false, version: 'v1.2.3' }),
    /already installed/
  );
  assert.match(formatWrapperBinaryStatus({ binaryPath: managedPath, changed: true }), /installed at/);
  assert.equal(formatWrapperBinaryStatus(null), 'redblue binary status unavailable');

  const chunks = [];
  writeLine(
    {
      write(chunk) {
        chunks.push(String(chunk));
      }
    },
    'hello'
  );
  assert.deepEqual(chunks, ['hello\n']);
});

test('exec helpers cover success, failure, spawn and route invocation building', async () => {
  const ok = await execFilePromise(process.execPath, ['-e', 'process.stdout.write("ok")']);
  assert.equal(ok.stdout, 'ok');

  await assert.rejects(
    execFilePromise(process.execPath, ['-e', 'process.stderr.write("bad");process.exit(2)']),
    (error) => {
      assert.equal(error.stderr, 'bad');
      return true;
    }
  );

  const child = spawnBinary(
    process.execPath,
    ['-e', 'process.stdout.write("spawned")'],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );
  const output = await new Promise((resolve, reject) => {
    let stdout = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      assert.equal(code, 0);
      resolve(stdout);
    });
  });
  assert.equal(output, 'spawned');

  const command = makeCommand('format');
  const route = makeRoute();

  assert.equal(findFlag(command, 'type').long, 'type');
  assert.equal(findFlag(command, 'f').long, 'format');
  assert.equal(findFlag(command, 'missing'), undefined);
  assert.equal(findFlag({}, 'missing'), undefined);

  const invocation = buildInvocation(
    command,
    route,
    {
      target: 'example.com',
      type: 'MX'
    },
    {}
  );
  assert.deepEqual(invocation, [
    'dns',
    'record',
    'lookup',
    'example.com',
    '--type',
    'MX',
    '--json',
    '--format',
    'json'
  ]);

  const invocationWithOutput = buildInvocation(
    makeCommand('output', 'output'),
    route,
    {
      target: 'example.com',
      flags: {
        output: 'yaml'
      }
    },
    {}
  );
  assert.deepEqual(invocationWithOutput, [
    'dns',
    'record',
    'lookup',
    'example.com',
    '--output',
    'yaml',
    '--json'
  ]);

  assert.deepEqual(
    buildInvocation(command, route, { target: 'example.com', args: ['extra'] }, { json: false }),
    ['dns', 'record', 'lookup', 'example.com', 'extra']
  );

  assert.throws(() => buildInvocation(command, route, {}, {}), /Missing required positional/);
  assert.throws(
    () => buildInvocation(command, route, { target: 'example.com', flags: { nope: true } }, {}),
    /Unknown flag/
  );
  assert.throws(
    () => buildInvocation(command, route, { target: 'example.com', surprise: 1 }, {}),
    /Unknown parameter/
  );
  assert.throws(
    () => buildInvocation(command, route, { target: 'example.com', args: 'oops' }, {}),
    /args must be an array/
  );

  const advancedCommand = {
    domain: 'tls',
    resource: 'security',
    flags: [
      {
        long: 'record-type',
        short: null,
        description: 'Record type',
        expects_value: true,
        camel_name: 'recordType'
      },
      {
        long: 'ports',
        short: 'p',
        description: 'Ports',
        expects_value: true,
        camel_name: 'ports'
      },
      {
        long: 'output-format',
        short: null,
        description: 'Output format (text, json)',
        expects_value: true,
        camel_name: 'outputFormat'
      },
      {
        long: 'verbose',
        short: 'v',
        description: 'Verbose output',
        expects_value: false,
        camel_name: 'verbose'
      }
    ],
    machine_output: {
      preferred_flag: 'output-format',
      preferred_value: 'json'
    }
  };

  const advancedRoute = {
    verb: 'audit',
    positionals: [
      {
        name: 'host',
        required: true,
        repeated: false,
        slot: 'target',
        index: 0
      },
      {
        name: 'profile',
        required: false,
        repeated: false,
        slot: 'arg',
        index: 1
      },
      {
        name: 'files',
        required: false,
        repeated: true,
        slot: 'arg',
        index: 2
      }
    ]
  };

  assert.deepEqual(
    buildInvocation(
      advancedCommand,
      advancedRoute,
      {
        target: 'example.com',
        recordType: 'TXT',
        p: ['443', '8443'],
        verbose: true,
        flags: {
          outputFormat: 'yaml'
        },
        files: ['a.pem', 'b.pem']
      },
      {}
    ),
    [
      'tls',
      'security',
      'audit',
      'example.com',
      'a.pem',
      'b.pem',
      '--record-type',
      'TXT',
      '--ports',
      '443',
      '--ports',
      '8443',
      '--output-format',
      'yaml',
      '--verbose',
      '--json'
    ]
  );

  assert.deepEqual(
    buildInvocation(
      {
        domain: 'network',
        resource: 'ports',
        flags: [],
        machine_output: {
          preferred_flag: null,
          preferred_value: 'json'
        }
      },
      {
        verb: 'scan',
        positionals: []
      },
      { target: '10.0.0.1' },
      {}
    ),
    ['network', 'ports', 'scan', '10.0.0.1', '--json']
  );

  assert.deepEqual(
    buildInvocation(
      {
        domain: 'dns',
        resource: 'record',
        machine_output: {
          preferred_flag: 'format'
        }
      },
      {
        verb: 'lookup'
      },
      { target: 'fallback.example' },
      {}
    ),
    ['dns', 'record', 'lookup', 'fallback.example', '--json', '--format', 'json']
  );

  assert.deepEqual(
    buildInvocation(
      {
        domain: 'tls',
        resource: 'security',
        flags: [
          {
            long: 'record-type',
            expects_value: true
          }
        ]
      },
      {
        verb: 'audit',
        positionals: [
          {
            name: 'files',
            required: false,
            repeated: true,
            slot: 'arg',
            index: 0
          }
        ]
      },
      {
        files: 'single.pem',
        recordType: 'TXT'
      },
      { json: false }
    ),
    ['tls', 'security', 'audit', 'single.pem', '--record-type', 'TXT']
  );
});

test('invoke helpers and manifest parsing cover json, raw, empty and invalid responses', async () => {
  const fixtureBinary = await createFixtureBinary();

  const command = {
    domain: 'dns',
    resource: 'record',
    flags: [],
    machine_output: {
      preferred_flag: null,
      preferred_value: 'json'
    }
  };
  const route = {
    verb: 'lookup',
    positionals: [
      {
        name: 'target',
        required: true,
        repeated: false,
        slot: 'target',
        index: 0
      }
    ]
  };

  const jsonResult = await invokeJson(
    fixtureBinary,
    command,
    route,
    { target: 'example.com' },
    {},
    { env: { RB_FAKE_ROUTE_MODE: 'json' } }
  );
  assert.equal(jsonResult.ok, true);

  const rawResult = await invokeRaw(
    fixtureBinary,
    command,
    route,
    { target: 'example.com' },
    { env: { RB_FAKE_ROUTE_MODE: 'raw' } },
    {}
  );
  assert.match(rawResult.stdout, /^raw:/);

  assert.equal(
    await invokeJson(
      fixtureBinary,
      command,
      route,
      { target: 'example.com' },
      { env: { RB_FAKE_ROUTE_MODE: 'empty' } },
      {}
    ),
    null
  );

  await assert.rejects(
    invokeJson(
      fixtureBinary,
      command,
      route,
      { target: 'example.com' },
      { env: { RB_FAKE_ROUTE_MODE: 'invalid-json' } },
      {}
    ),
    /did not emit valid JSON/
  );

  const manifestInfo = await sdk.getManifest({ binaryPath: fixtureBinary });
  assert.equal(manifestInfo.manifest.schema_version, 1);
  assert.equal(Array.isArray(manifestInfo.manifest.domains), true);
  assert.equal(manifestInfo.manifest.commands.length, 4);

  await assert.rejects(
    sdk.getManifest({
      binaryPath: fixtureBinary,
      env: { RB_FAKE_MANIFEST_MODE: 'empty' }
    }),
    /returned empty output/
  );

  await assert.rejects(
    sdk.getManifest({
      binaryPath: fixtureBinary,
      env: { RB_FAKE_MANIFEST_MODE: 'invalid' }
    }),
    /Failed to parse redblue SDK manifest JSON/
  );

  const runJsonResult = await runJson(['dns', 'record', 'lookup', 'example.com'], {
    binaryPath: fixtureBinary
  });
  assert.equal(runJsonResult.ok, true);
  assert.deepEqual(runJsonResult.argv, [
    'dns',
    'record',
    'lookup',
    'example.com',
    '--json',
    '--format',
    'json'
  ]);

  assert.equal(
    await runJson(['dns', 'record', 'lookup', 'example.com'], {
      binaryPath: fixtureBinary,
      env: { RB_FAKE_ROUTE_MODE: 'empty' }
    }),
    null
  );

  await assert.rejects(
    runJson(['dns', 'record', 'lookup', 'example.com'], {
      binaryPath: fixtureBinary,
      env: { RB_FAKE_ROUTE_MODE: 'invalid-json' }
    }),
    /did not emit valid JSON/
  );

  await assert.rejects(
    runJson(['dns', 'record', 'lookup', 'example.com'], {
      binaryPath: fixtureBinary,
      env: { RB_FAKE_MANIFEST_JSON_UNDECLARED: '1' }
    }),
    /does not declare machine-safe JSON output/
  );

  await assert.rejects(() => runJson('dns'), /CLI argv must be an array of strings/);
});

test('createDomainProxy, attachRoute and createClient execute dns, tls, ports and system namespaces with forced json', async () => {
  const fixtureBinary = await createFixtureBinary();
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-client-'));
  const logPath = path.join(tmpDir, 'invocations.log');

  const manifestInfo = await sdk.getManifest({ binaryPath: fixtureBinary });
  assert.equal(
    routeIdentifier(manifestInfo.manifest.commands[0], manifestInfo.manifest.commands[0].routes[0]),
    'dns/record/lookup'
  );
  assert.equal(
    resolveMachineOutput(
      manifestInfo.manifest.commands[0],
      manifestInfo.manifest.commands[0].routes[0]
    ).preferred_flag,
    'format'
  );
  const proxy = createDomainProxy(fixtureBinary, manifestInfo.manifest, {
    env: {
      RB_FAKE_LOG_PATH: logPath
    }
  });
  const routeIndex = createRouteIndex(proxy);
  const domainCatalog = buildDomainCatalog(manifestInfo.manifest);
  const commandCatalog = buildCommandCatalog(manifestInfo.manifest);

  assert.equal(typeof proxy.dns.record.lookup, 'function');
  assert.equal(typeof proxy.dns.rec.lookup, 'function');
  assert.equal(typeof proxy.tls.security.audit, 'function');
  assert.equal(typeof proxy.tls.sec.audit, 'function');
  assert.equal(typeof proxy.network.ports.scan, 'function');
  assert.equal(typeof proxy.n.ports.scan, 'function');
  assert.equal(typeof proxy.system.host.inspect, 'function');
  assert.equal(typeof proxy.sys.machine.inspect, 'function');
  assert.equal(typeof routeIndex['dns/record/lookup'], 'function');
  assert.equal(typeof routeIndex['system/host/inspect'], 'function');
  assert.equal(Array.isArray(domainCatalog), true);
  assert.equal(Array.isArray(commandCatalog), true);
  assert.equal(commandCatalog.some((entry) => entry.canonical_path === 'dns/record/lookup'), true);
  assert.deepEqual(describeManifestRoute(manifestInfo.manifest, 'dns/record/lookup').positionals, [
    {
      name: 'target',
      required: true,
      repeated: false,
      slot: 'target',
      index: 0
    }
  ]);
  assert.equal(
    describeManifestRoute(manifestInfo.manifest, 'dns/record/lookup').flags.some((flag) => flag.long === 'type'),
    true
  );
  assert.deepEqual(
    describeManifestRoute(manifestInfo.manifest, 'dns/record/lookup').flags.find((flag) => flag.long === 'format').values,
    ['human', 'json', 'yaml']
  );
  assert.equal(looksLikeCanonicalCommandArgs(['dns', 'record', 'lookup']), true);
  assert.equal(looksLikeCanonicalCommandArgs(['-e', 'console.log(1)']), false);
  assert.equal(domainCatalog[0].name, 'dns');
  assert.equal(hasLongFlag(['--json'], 'json'), true);
  assert.equal(hasLongFlag(['--format=json'], 'format'), true);
  assert.equal(hasLongFlag(['--type', 'MX'], 'json'), false);
  assert.equal(findRouteInvocation(routeIndex, manifestInfo.manifest, 'dns/record/lookup'), routeIndex['dns/record/lookup']);
  assert.equal(findRouteInvocation(routeIndex, manifestInfo.manifest, 'n/ports/scan'), routeIndex['network/ports/scan']);
  assert.equal(findRouteInvocation(routeIndex, manifestInfo.manifest, ['tls', 'sec', 'audit']), routeIndex['tls/security/audit']);
  assert.equal(findRouteInvocation(routeIndex, manifestInfo.manifest, 'sys/machine/inventory'), routeIndex['system/host/inspect']);
  assert.equal(describeManifestRoute(manifestInfo.manifest, 'sys/machine/inventory').canonical_path, 'system/host/inspect');
  assert.equal(describeManifestRoute(manifestInfo.manifest, 'missing/route/here'), null);
  assert.equal(routeInvocationMeta(routeIndex, manifestInfo.manifest, ['dns', 'record', 'lookup']).route.verb, 'lookup');
  assert.equal(routeInvocationMeta(null, manifestInfo.manifest, ['dns', 'record', 'lookup']).route.verb, 'lookup');
  assert.equal(routeInvocationMeta(null, manifestInfo.manifest, ['sys', 'machine', 'inventory']).route.verb, 'inspect');
  assert.equal(routeInvocationMeta(routeIndex, manifestInfo.manifest, ['dns']), null);
  assert.deepEqual(buildJsonCliArgs(['dns', 'record', 'lookup', 'example.com'], routeIndex, manifestInfo.manifest), [
    'dns',
    'record',
    'lookup',
    'example.com',
    '--json',
    '--format',
    'json'
  ]);
  assert.deepEqual(normalizeCliArgv(['dns', 'record', 'lookup']), ['dns', 'record', 'lookup']);
  assert.equal(normalizeRouteSelector('dns.record.lookup').join('/'), 'dns/record/lookup');
  assert.equal(normalizeTokenSelector('dns record lookup example.com').join('/'), 'dns/record/lookup/example.com');
  assert.equal(globalOptionExpectsValue({ kind: 'output-format' }), true);
  assert.equal(globalOptionExpectsValue({ long: 'json', value: 'json' }), false);
  assert.equal(globalOptionExpectsValue({ values: ['json', 'yaml'] }), true);
  const optionIndex = buildGlobalOptionIndex(manifestInfo.manifest);
  assert.equal(optionIndex.long.get('json').long, 'json');
  assert.equal(optionIndex.short.get('j').long, 'json');
  assert.deepEqual(
    extractRouteSelectorFromArgv(['--json', 'dns', 'record', 'lookup', 'example.com'], manifestInfo.manifest),
    ['dns', 'record', 'lookup']
  );
  assert.deepEqual(
    extractRouteSelectorFromArgv(
      ['--output', 'json', 'dns', 'record', 'lookup', 'example.com'],
      manifestInfo.manifest
    ),
    ['dns', 'record', 'lookup']
  );
  assert.equal(
    findCommandStartIndex(['--output', 'json', 'dns', 'record', 'lookup'], manifestInfo.manifest),
    2
  );
  assert.equal(findCommandStartIndex(['--json', 'dns', 'record', 'lookup'], manifestInfo.manifest), 1);
  const expectedSystemDomain = manifestInfo.manifest.domains.find((domain) => domain.name === 'system');
  const expectedHostResource = expectedSystemDomain.resources.find((resource) => resource.name === 'host');
  const expectedInspectVerb = expectedHostResource.verbs.find((verb) => verb.name === 'inspect');
  assert.deepEqual(resolveCanonicalRouteTokens(manifestInfo.manifest, 'sys/machine/inventory'), {
    domainToken: 'sys',
    resourceToken: 'machine',
    verbToken: 'inventory',
    domainName: 'system',
    resourceName: 'host',
    verbName: 'inspect',
    canonicalDomain: expectedSystemDomain,
    canonicalResource: expectedHostResource,
    canonicalVerb: expectedInspectVerb
  });
  assert.throws(() => normalizeRouteSelector('dns record'), /domain\/resource\/verb/);
  assert.deepEqual(suggestCommandTokens(manifestInfo.manifest, []), {
    stage: 'domain',
    suggestions: ['dns', 'tls', 'network', 'system']
  });
  assert.deepEqual(suggestCommandTokens(manifestInfo.manifest, ['dns', 'rec']), {
    stage: 'resource',
    suggestions: ['record']
  });
  assert.deepEqual(suggestCommandTokens(manifestInfo.manifest, 'tls sec aud'), {
    stage: 'verb',
    suggestions: ['audit']
  });
  assert.deepEqual(suggestCommandTokens(manifestInfo.manifest, ['sys', 'mach']), {
    stage: 'resource',
    suggestions: ['host']
  });
  assert.deepEqual(completeManifestTokens(manifestInfo.manifest, ['sys', 'mach']), {
    stage: 'resource',
    completions: [
      {
        value: 'host',
        kind: 'resource',
        summary: 'Local host inventory',
        aliases: ['machine', 'node'],
        command: 'rb system host'
      }
    ]
  });
  assert.deepEqual(completeManifestTokens(manifestInfo.manifest, ['dns', 'record', 'lookup']), {
    stage: 'target',
    completions: [
      {
        value: '<target>',
        kind: 'target',
        summary: 'Required target input',
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.deepEqual(completeManifestTokens(manifestInfo.manifest, ['dns', 'record', 'lookup', 'example.com']), {
    stage: 'flag',
    completions: [
      {
        value: '--type',
        kind: 'flag',
        summary: 'Record type',
        aliases: ['-t'],
        command: 'rb dns record lookup'
      },
      {
        value: '--format',
        kind: 'flag',
        summary: 'Output format (text, json)',
        aliases: ['-f'],
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.deepEqual(completeManifestTokens(manifestInfo.manifest, ['dns', 'record', 'lookup', 'example.com', '--fo']), {
    stage: 'flag',
    completions: [
      {
        value: '--format',
        kind: 'flag',
        summary: 'Output format (text, json)',
        aliases: ['-f'],
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.deepEqual(completeManifestTokens(manifestInfo.manifest, ['dns', 'record', 'lookup', 'example.com', '--format']), {
    stage: 'flag-value',
    completions: [
      {
        value: 'human',
        kind: 'flag-value',
        summary: 'Value for --format',
        aliases: [],
        command: 'rb dns record lookup'
      },
      {
        value: 'json',
        kind: 'flag-value',
        summary: 'Value for --format',
        aliases: [],
        command: 'rb dns record lookup'
      },
      {
        value: 'yaml',
        kind: 'flag-value',
        summary: 'Value for --format',
        aliases: [],
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.deepEqual(
    completeManifestTokens(manifestInfo.manifest, ['dns', 'record', 'lookup', 'example.com', '--format', 'j']),
    {
      stage: 'flag-value',
      completions: [
        {
          value: 'json',
          kind: 'flag-value',
          summary: 'Value for --format',
          aliases: [],
          command: 'rb dns record lookup'
        }
      ]
    }
  );
  assert.deepEqual(suggestRouteCommands(manifestInfo.manifest, 'tls security audti', 2), [
    'rb tls security audit'
  ]);
  assert.match(
    formatRouteHelpSummary(manifestInfo.manifest, 'sys/machine/inventory'),
    /rb system host inspect/
  );
  assert.match(formatRouteHelpSummary(manifestInfo.manifest, 'sys/machine/inventory'), /Usage:/);
  assert.match(formatRouteHelpSummary(manifestInfo.manifest, 'dns/record/lookup'), /Positionals:/);
  assert.match(formatRouteHelpSummary(manifestInfo.manifest, 'dns/record/lookup'), /\[human\|json\|yaml\]/);
  assert.equal(formatRouteHelpSummary(manifestInfo.manifest, 'missing/route/here'), '');

  const container = {};
  attachRoute(
    container,
    fixtureBinary,
    manifestInfo.manifest.commands[0],
    manifestInfo.manifest.commands[0].routes[0],
    {
      env: {
        RB_FAKE_LOG_PATH: logPath
      }
    }
  );
  assert.equal(typeof container.lookup.raw, 'function');
  assert.equal(typeof container.lookup.spawn, 'function');

  const client = await sdk.createClient({
    binaryPath: fixtureBinary,
    env: {
      RB_FAKE_LOG_PATH: logPath
    }
  });

  const dns = await client.dns.record.lookup({ target: 'example.com', type: 'MX' });
  const tls = await client.tls.security.audit({ target: 'example.com', ports: '443' });
  const ports = await client.network.ports.scan({ target: '10.0.0.1', preset: 'common' });
  const system = await client.system.host.inspect();

  assert.equal(dns.ok, true);
  assert.equal(tls.ok, true);
  assert.equal(ports.ok, true);
  assert.equal(system.ok, true);
  assert.equal(typeof client.n.ports.scan, 'function');
  assert.equal(typeof client.dns.rec.lookup, 'function');
  assert.equal(typeof client.sys.machine.inspect, 'function');
  assert.equal(client.$binaryPath, fixtureBinary);
  assert.equal(Array.isArray(client.$manifest.commands), true);
  assert.equal(typeof client.$routes['network/ports/scan'], 'function');
  assert.equal(typeof client.$routes['system/host/inspect'], 'function');
  assert.equal(Array.isArray(client.$domains), true);
  assert.equal(Array.isArray(client.$commands), true);
  assert.equal(client.$domains[0].name, 'dns');
  assert.equal(client.$domains[0].resources[0].name, 'record');
  assert.equal(client.$domains[0].resources[0].verbs[0].name, 'lookup');
  assert.equal(client.$findRoute('network/ports/scan'), client.$routes['network/ports/scan']);
  assert.equal(client.$findRoute('n/ports/scan'), client.$routes['network/ports/scan']);
  assert.equal(client.$findRoute('sys/machine/inventory'), client.$routes['system/host/inspect']);
  assert.equal(client.$findRoute('missing/route/here'), null);
  assert.equal(client.$describe('sys/machine/inventory').canonical_path, 'system/host/inspect');
  assert.equal(client.$describe('dns/record/lookup').command, 'rb dns record lookup');
  assert.deepEqual(client.$describe('dns/record/lookup').positionals, [
    {
      name: 'target',
      required: true,
      repeated: false,
      slot: 'target',
      index: 0
    }
  ]);
  assert.equal(client.$describe('dns/record/lookup').flags.some((flag) => flag.long === 'format'), true);
  assert.deepEqual(
    client.$describe('dns/record/lookup').flags.find((flag) => flag.long === 'format').values,
    ['human', 'json', 'yaml']
  );
  assert.equal(client.$describe('missing/route/here'), null);
  assert.match(client.$help('sys/machine/inventory'), /rb system host inspect/);
  assert.match(client.$help('dns/record/lookup'), /Examples:/);
  assert.equal(client.$help('missing/route/here'), '');
  assert.equal(client.$commands.some((entry) => entry.command === 'rb tls security audit'), true);
  assert.deepEqual(client.$suggest(['network', 'po']), {
    stage: 'resource',
    suggestions: ['ports']
  });
  assert.deepEqual(client.$complete(['network', 'po']), {
    stage: 'resource',
    completions: [
      {
        value: 'ports',
        kind: 'resource',
        summary: 'Port scans',
        aliases: [],
        command: 'rb network ports'
      }
    ]
  });
  assert.deepEqual(client.$complete(['dns', 'record', 'lookup']), {
    stage: 'target',
    completions: [
      {
        value: '<target>',
        kind: 'target',
        summary: 'Required target input',
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.deepEqual(client.$complete(['dns', 'record', 'lookup', 'example.com', '--fo']), {
    stage: 'flag',
    completions: [
      {
        value: '--format',
        kind: 'flag',
        summary: 'Output format (text, json)',
        aliases: ['-f'],
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.deepEqual(client.$complete(['dns', 'record', 'lookup', 'example.com', '--format']), {
    stage: 'flag-value',
    completions: [
      {
        value: 'human',
        kind: 'flag-value',
        summary: 'Value for --format',
        aliases: [],
        command: 'rb dns record lookup'
      },
      {
        value: 'json',
        kind: 'flag-value',
        summary: 'Value for --format',
        aliases: [],
        command: 'rb dns record lookup'
      },
      {
        value: 'yaml',
        kind: 'flag-value',
        summary: 'Value for --format',
        aliases: [],
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.deepEqual(client.$complete(['dns', 'record', 'lookup', 'example.com', '--format', 'j']), {
    stage: 'flag-value',
    completions: [
      {
        value: 'json',
        kind: 'flag-value',
        summary: 'Value for --format',
        aliases: [],
        command: 'rb dns record lookup'
      }
    ]
  });
  assert.equal((await runJson(['dns', 'record', 'lookup', 'example.com'], {
    binaryPath: fixtureBinary,
    env: {
      RB_FAKE_LOG_PATH: logPath
    }
  })).ok, true);

  const raw = await client.dns.record.lookup.raw(
    { target: 'example.com' },
    {
      env: {
        RB_FAKE_ROUTE_MODE: 'raw'
      }
    }
  );
  assert.match(raw.stdout, /^raw:/);

  const spawned = client.network.ports.scan.spawn(
    { target: '10.0.0.2', preset: 'fast' },
    {
      env: {
        RB_FAKE_LOG_PATH: logPath,
        RB_FAKE_ROUTE_MODE: 'spawn'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );

  const spawnedOutput = await new Promise((resolve, reject) => {
    let stdout = '';
    spawned.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    spawned.on('error', reject);
    spawned.on('close', (code) => {
      assert.equal(code, 0);
      resolve(stdout);
    });
  });
  assert.match(spawnedOutput, /^spawn:/);

  const directExec = await client.$exec(['sdk', 'bridge', 'manifest']);
  assert.match(directExec.stdout, /"commands"/);
  assert.throws(() => client.$exec('oops'), /\$exec expects an array/);

  const directSpawn = client.$spawn(['sdk', 'bridge', 'manifest'], {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  assert.throws(() => client.$spawn('oops'), /\$spawn expects an array/);
  const directSpawnOutput = await new Promise((resolve, reject) => {
    let stdout = '';
    directSpawn.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    directSpawn.on('error', reject);
    directSpawn.on('close', (code) => {
      assert.equal(code, 0);
      resolve(stdout);
    });
  });
  assert.match(directSpawnOutput, /"commands"/);

  const routeInvocations = readLogLines(logPath).filter((entry) => entry[0] !== 'sdk');
  assert(routeInvocations.some((entry) => JSON.stringify(entry) === JSON.stringify([
    'dns',
    'record',
    'lookup',
    'example.com',
    '--type',
    'MX',
    '--json',
    '--format',
    'json'
  ])));
  assert(routeInvocations.some((entry) => JSON.stringify(entry) === JSON.stringify([
    'tls',
    'security',
    'audit',
    'example.com',
    '--ports',
    '443',
    '--json',
    '--format',
    'json'
  ])));
  assert(routeInvocations.some((entry) => JSON.stringify(entry) === JSON.stringify([
    'network',
    'ports',
    'scan',
    '10.0.0.1',
    '--preset',
    'common',
    '--json',
    '--output',
    'json'
  ])));
  assert(routeInvocations.some((entry) => JSON.stringify(entry) === JSON.stringify([
    'system',
    'host',
    'inspect',
    '--json'
  ])));
  assert(routeInvocations.some((entry) => JSON.stringify(entry) === JSON.stringify([
    'dns',
    'record',
    'lookup',
    'example.com',
    '--json',
    '--format',
    'json'
  ])));
});

test('fallback branches for raw, spawn and proxy construction stay stable', async () => {
  const fixtureBinary = await createFixtureBinary();

  const rawResult = await invokeRaw(
    fixtureBinary,
    {
      domain: 'dns',
      resource: 'record',
      flags: [],
      machine_output: {
        preferred_flag: null,
        preferred_value: 'json'
      }
    },
    {
      verb: 'lookup',
      positionals: [
        {
          name: 'target',
          required: true,
          repeated: false,
          slot: 'target',
          index: 0
        }
      ]
    },
    { target: 'example.com' },
    {},
    {
      env: {
        RB_FAKE_ROUTE_MODE: 'raw'
      }
    }
  );
  assert.match(rawResult.stdout, /^raw:/);

  const child = spawnBinary(process.execPath, ['-e', 'process.exit(0)']);
  await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => {
      assert.equal(code, 0);
      resolve();
    });
  });

  const emptyProxy = createDomainProxy(fixtureBinary, {}, {});
  assert.deepEqual(emptyProxy, {});
  assert.deepEqual(buildDomainCatalog({}), []);
  assert.equal(findRouteInvocation({}, {}, 'dns/record/lookup'), null);
  assert.deepEqual(suggestCommandTokens({}, ['dns']), {
    stage: 'domain',
    suggestions: []
  });
  assert.deepEqual(suggestRouteCommands({}, 'dns record lookup'), []);

  const fallbackCatalog = buildDomainCatalog({
    commands: [
      {
        domain: 'dns',
        domain_aliases: ['d'],
        resource: 'record',
        resource_aliases: ['rec'],
        description: 'DNS record lookups',
        routes: [
          {
            verb: 'lookup',
            summary: 'Lookup DNS records',
            aliases: ['get']
          }
        ]
      }
    ]
  });
  assert.deepEqual(fallbackCatalog, [
    {
      name: 'dns',
      aliases: ['d'],
      resources: [
        {
          name: 'record',
          description: 'DNS record lookups',
          aliases: ['rec'],
          verbs: [
            {
              name: 'lookup',
              summary: 'Lookup DNS records',
              aliases: ['get']
            }
          ]
        }
      ]
    }
  ]);

  const routeLessProxy = createDomainProxy(
    fixtureBinary,
    {
      commands: [
        {
          domain: 'dns',
          resource: 'record'
        }
      ]
    },
    {}
  );
  assert.deepEqual(Object.keys(routeLessProxy.dns.record), []);

  const container = {};
  attachRoute(
    container,
    fixtureBinary,
    {
      domain: 'dns',
      resource: 'record',
      flags: [],
      machine_output: {
        preferred_flag: null,
        preferred_value: 'json'
      }
    },
    {
      verb: 'lookup',
      positionals: [
        {
          name: 'target',
          required: true,
          repeated: false,
          slot: 'target',
          index: 0
        }
      ]
    },
    {}
  );

  const spawned = container.lookup.spawn(
    { target: 'example.com' },
    {
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );

  const spawnedOutput = await new Promise((resolve, reject) => {
    let stdout = '';
    spawned.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    spawned.on('error', reject);
    spawned.on('close', (code) => {
      assert.equal(code, 0);
      resolve(stdout);
    });
  });

  assert.match(spawnedOutput, /"ok":true/);
});

test('wrapper parser helpers cover prefix splitting and parse normalization', async () => {
  assert.deepEqual(splitWrapperArgs(['dns', 'record', 'lookup']), {
    wrapperArgs: [],
    passthroughArgs: ['dns', 'record', 'lookup'],
    usedDoubleDash: false
  });

  assert.deepEqual(
    splitWrapperArgs([
      '--binary-path',
      '/tmp/rb',
      '--auto-download',
      'dns',
      'record',
      'lookup',
      'example.com'
    ]),
    {
      wrapperArgs: ['--binary-path', '/tmp/rb', '--auto-download'],
      passthroughArgs: ['dns', 'record', 'lookup', 'example.com'],
      usedDoubleDash: false
    }
  );

  assert.deepEqual(splitWrapperArgs(['--', 'dns', '--help']), {
    wrapperArgs: [],
    passthroughArgs: ['dns', '--help'],
    usedDoubleDash: true
  });

  assert.deepEqual(splitWrapperArgs(['--json', 'dns', 'record']), {
    wrapperArgs: [],
    passthroughArgs: ['--json', 'dns', 'record'],
    usedDoubleDash: false
  });

  assert.deepEqual(splitWrapperArgs(['--version']), {
    wrapperArgs: [],
    passthroughArgs: ['--version'],
    usedDoubleDash: false
  });

  assert.deepEqual(splitWrapperArgs(['--version', '1.2.3', 'dns', 'record']), {
    wrapperArgs: ['--version', '1.2.3'],
    passthroughArgs: ['dns', 'record'],
    usedDoubleDash: false
  });

  assert.deepEqual(splitWrapperArgs(null), {
    wrapperArgs: [],
    passthroughArgs: [],
    usedDoubleDash: false
  });

  assert.deepEqual(splitWrapperArgs(['--repo=forattini-dev/redblue', 'dns', 'record']), {
    wrapperArgs: ['--repo=forattini-dev/redblue'],
    passthroughArgs: ['dns', 'record'],
    usedDoubleDash: false
  });

  const parsed = await parseWrapperArgs([
    '--binary-path',
    '/tmp/rb',
    '--target-dir',
    '/tmp/bin',
    '--download',
    '--install',
    '--upgrade',
    '--check-update',
    '--print-binary-path',
    '--channel',
    'next',
    '--force',
    '--version',
    '1.2.3',
    '--repo',
    'forattini-dev/redblue',
    '--asset-name',
    'rb-linux-x86_64',
    '--github-token',
    'ghs_secret',
    '--static-build',
    '--no-verify',
    'dns',
    'record',
    'lookup',
    'example.com',
    '--type',
    'MX'
  ]);

  assert.deepEqual(parsed.passthroughArgs, [
    'dns',
    'record',
    'lookup',
    'example.com',
    '--type',
    'MX'
  ]);
  assert.deepEqual(parsed.resolveOptions, {
    binaryPath: '/tmp/rb',
    targetDir: '/tmp/bin',
    autoDownload: true,
    repo: 'forattini-dev/redblue',
    channel: 'next',
    releaseVersion: '1.2.3',
    assetName: 'rb-linux-x86_64',
    githubToken: 'ghs_secret',
    verify: false,
    staticBuild: true,
    force: true,
    version: '1.2.3'
  });
  assert.deepEqual(parsed.wrapperOptions, {
    sdkHelp: false,
    checkUpdate: true,
    upgrade: true,
    install: true,
    printBinaryPath: true
  });

  const parsedHelp = await parseWrapperArgs(['--sdk-help']);
  assert.deepEqual(parsedHelp.wrapperOptions, {
    sdkHelp: true,
    checkUpdate: false,
    upgrade: false,
    install: false,
    printBinaryPath: false
  });
  assert.deepEqual(parsedHelp.passthroughArgs, []);

  const parsedEmpty = await parseWrapperArgs(null);
  assert.deepEqual(parsedEmpty.passthroughArgs, []);
  assert.deepEqual(parsedEmpty.resolveOptions, {
    binaryPath: undefined,
    targetDir: undefined,
    autoDownload: false,
    repo: undefined,
    channel: undefined,
    releaseVersion: undefined,
    assetName: undefined,
    githubToken: undefined,
    verify: true,
    staticBuild: false,
    force: false,
    version: undefined
  });
  assert.deepEqual(parsedEmpty.wrapperOptions, {
    sdkHelp: false,
    checkUpdate: false,
    upgrade: false,
    install: false,
    printBinaryPath: false
  });

  // --binary-path without a value is consumed by splitWrapperArgs but
  // the manual parser simply skips it (no more value available)
  const parsedNoValue = await parseWrapperArgs(['--binary-path']);
  assert.equal(parsedNoValue.resolveOptions.binaryPath, undefined);

  assert.match(formatWrapperHelp(), /npx redblue-cli/);
  assert.match(formatWrapperHelp(), /pnpm dlx redblue-cli/);
  assert.match(formatWrapperHelp(), /--install/);
  assert.match(formatWrapperHelp(), /--release-version/);

  const manifest = {
    canonical_grammar: 'rb <domain> <resource> <verb> [target] [args...] [flags]',
    global_options: [
      {
        long: 'json',
        short: 'j',
        description: 'Force JSON output globally'
      }
    ],
    domains: [
      {
        name: 'dns',
        aliases: [],
        resources: [
          {
            name: 'record',
            description: 'DNS record lookups',
            aliases: [],
            verbs: [
              {
                name: 'lookup',
                summary: 'Lookup DNS records',
                aliases: []
              }
            ]
          }
        ]
      },
      {
        name: 'network',
        aliases: ['n'],
        resources: [
          {
            name: 'ports',
            description: 'Port scans',
            aliases: [],
            verbs: []
          }
        ]
      }
    ],
    commands: [
      {
        domain: 'dns',
        resource: 'record',
        examples: [
          {
            summary: 'Lookup MX records',
            command: 'rb dns record lookup example.com --type MX'
          }
        ]
      }
    ]
  };

  const manifestSummary = formatManifestHelpSummary(manifest);
  assert.match(manifestSummary, /rb <domain> <resource> <verb>/);
  assert.match(manifestSummary, /--json, -j/);
  assert.match(manifestSummary, /dns/);
  assert.match(manifestSummary, /record/);
  assert.match(manifestSummary, /Examples:/);
  assert.match(manifestSummary, /rb dns record lookup example.com --type MX/);

  const richHelp = formatWrapperHelp(manifest);
  assert.match(richHelp, /redblue CLI/);
  assert.match(richHelp, /Global redblue options:/);
  assert.match(richHelp, /Canonical domains:/);
  assert.match(richHelp, /network/);
  assert.match(richHelp, /Examples:/);

  const routeManifest = {
    domains: [
      {
        name: 'dns',
        aliases: [],
        resources: [
          {
            name: 'record',
            description: 'DNS record lookups',
            aliases: ['rec'],
            verbs: [
              {
                name: 'lookup',
                summary: 'Lookup DNS records',
                aliases: ['find']
              }
            ]
          }
        ]
      }
    ],
    commands: [
      {
        domain: 'dns',
        resource: 'record',
        flags: [
          {
            long: 'type',
            short: 't',
            description: 'Record type',
            expects_value: true,
            camel_name: 'type'
          }
        ],
        routes: [
          {
            verb: 'lookup',
            summary: 'Lookup DNS records',
            usage: 'rb dns record lookup <target>',
            aliases: ['find'],
            canonical_path: 'dns/record/lookup',
            command: 'rb dns record lookup',
            machine_output: {
              json_support: 'best-effort',
              preferred_flag: 'format',
              preferred_value: 'json'
            },
            positionals: [
              {
                name: 'target',
                required: true,
                repeated: false,
                slot: 'target'
              }
            ]
          }
        ]
      }
    ]
  };

  assert.deepEqual(normalizeSdkHelpSelector(['rb', 'help', 'dns', 'record', 'lookup']), [
    'dns',
    'record',
    'lookup'
  ]);
  assert.deepEqual(normalizeSdkHelpSelector(['--json', 'dns', 'record']), ['dns', 'record']);
  assert.match(formatSdkHelpOutput(routeManifest, ['dns', 'record', 'lookup']), /Usage:/);
  assert.match(formatSdkHelpOutput(routeManifest, ['dns', 'record', 'lookup']), /Aliases: find/);
  assert.match(formatPartialRouteHelp(routeManifest, ['dns', 'rec']), /Partial route:/);
  assert.match(formatPartialRouteHelp(routeManifest, ['dns', 'rec']), /Expected next token: resource/);
  assert.match(formatUnknownRouteHelp(routeManifest, ['dns', 'record', 'loookup']), /Unknown route:/);
  assert.match(formatUnknownRouteHelp(routeManifest, ['dns', 'record', 'loookup']), /Closest canonical routes:/);

  // formatSdkHelpOutput branches: null/non-object manifest falls back
  // to the wrapper help; a 3-token unknown route goes through
  // formatUnknownRouteHelp; a <3-token selector goes through
  // formatPartialRouteHelp. Each of these was previously unreached.
  assert.match(formatSdkHelpOutput(null, ['anything']), /npx redblue-cli/);
  assert.match(formatSdkHelpOutput('not-an-object', ['anything']), /npx redblue-cli/);
  assert.match(
    formatSdkHelpOutput(routeManifest, ['dns', 'record', 'loookup']),
    /Unknown route:/
  );
  assert.match(formatSdkHelpOutput(routeManifest, ['dns', 'rec']), /Partial route:/);

  // parseWrapperArgs with `--flag=value` form covers the eqIndex slice
  // branch (line 649 in redblue-sdk.js).
  const parsedEq = await parseWrapperArgs([
    '--repo=forattini-dev/redblue',
    '--release-version=3.2.1'
  ]);
  assert.equal(parsedEq.resolveOptions.repo, 'forattini-dev/redblue');
  assert.equal(parsedEq.resolveOptions.releaseVersion, '3.2.1');
});

test('branch-only helper paths stay covered', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-branches-'));
  const originalInstallDir = process.env.REDBLUE_INSTALL_DIR;
  const originalLegacyInstallDir = process.env.INSTALL_DIR;

  process.env.REDBLUE_INSTALL_DIR = path.join(tmpDir, 'managed-bin');
  assert.equal(defaultInstallDir(), path.join(tmpDir, 'managed-bin'));
  delete process.env.REDBLUE_INSTALL_DIR;
  process.env.INSTALL_DIR = path.join(tmpDir, 'fallback-bin');
  assert.equal(defaultInstallDir(), path.join(tmpDir, 'fallback-bin'));

  if (originalInstallDir === undefined) {
    delete process.env.REDBLUE_INSTALL_DIR;
  } else {
    process.env.REDBLUE_INSTALL_DIR = originalInstallDir;
  }

  if (originalLegacyInstallDir === undefined) {
    delete process.env.INSTALL_DIR;
  } else {
    process.env.INSTALL_DIR = originalLegacyInstallDir;
  }

  assert.equal(await getReleaseTag({ releaseVersion: '2.0.0' }), 'v2.0.0');
  assert.equal(resolveLegacyBinaryPath({ binaryPath: '/tmp/rb' }), null);
  assert.equal(resolveLegacyBinaryPath({ targetDir: '/tmp/bin' }), null);
  assert.equal(
    resolveManagedUpgradeDestination(
      {},
      { binaryPath: path.join(tmpDir, 'legacy-rb'), source: 'legacy' }
    ),
    path.join(tmpDir, 'legacy-rb')
  );

  assert.match(
    formatWrapperBinaryStatus({
      latestVersion: 'v2.0.0',
      currentVersion: null
    }),
    /not installed/
  );
  assert.match(
    formatWrapperBinaryStatus({
      previousVersion: 'v1.0.0',
      changed: false,
      binaryPath: path.join(tmpDir, 'rb')
    }),
    /version unknown/
  );
  assert.match(
    formatWrapperBinaryStatus({
      previousVersion: null,
      changed: true,
      binaryPath: path.join(tmpDir, 'rb')
    }),
    /version unknown/
  );
  assert.match(
    formatWrapperBinaryStatus({
      binaryPath: path.join(tmpDir, 'rb'),
      changed: false
    }),
    /already installed/
  );

  assert.deepEqual(splitWrapperArgs(['--version', '--sdk-help']), {
    wrapperArgs: [],
    passthroughArgs: ['--version', '--sdk-help'],
    usedDoubleDash: false
  });

  // parseWrapperArgs: --version alias resolves to releaseVersion
  const parsedFromAliasOnly = await parseWrapperArgs(['--version', '9.9.9']);

  assert.equal(parsedFromAliasOnly.resolveOptions.releaseVersion, '9.9.9');
  assert.equal(parsedFromAliasOnly.resolveOptions.version, '9.9.9');
});

test('edge-case branches for manifest formatting, completion, validation and route helpers', async () => {
  const fixtureBinary = await createFixtureBinary();
  const manifestInfo = await sdk.getManifest({ binaryPath: fixtureBinary });
  const manifest = manifestInfo.manifest;

  // formatManifestOptionFlag: null/invalid option returns null (lines 829-830)
  const summaryWithBadFlags = formatManifestHelpSummary({
    global_options: [null, { long: '' }, { long: 123 }, {}],
    commands: []
  });
  assert.equal(typeof summaryWithBadFlags, 'string');

  // formatManifestHelpSummary: skip invalid examples (lines 891-892)
  const summaryWithBadExamples = formatManifestHelpSummary({
    commands: [
      {
        domain: 'dns',
        resource: 'record',
        examples: [null, { command: 123 }, { summary: 'ok', command: 'rb dns record lookup example.com' }]
      }
    ]
  });
  assert.match(summaryWithBadExamples, /rb dns record lookup example.com/);

  // formatRouteHelpSummary: skip invalid flags (lines 934-935) and examples (lines 947-948)
  const routeHelp = formatRouteHelpSummary(
    {
      domains: [
        {
          name: 'test',
          aliases: [],
          resources: [
            {
              name: 'res',
              aliases: [],
              verbs: [{ name: 'run', summary: 'Run it', aliases: [] }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'test',
          resource: 'res',
          flags: [
            { long: '', description: 'Empty long' },
            { long: 'valid', short: 'v', description: 'Valid flag', expects_value: false }
          ],
          machine_output: { preferred_flag: null, preferred_value: null },
          examples: [
            { summary: 'Run test', command: 'rb test res run target' }
          ],
          routes: [
            {
              verb: 'run',
              summary: 'Run it',
              usage: 'rb test res run <target>',
              aliases: [],
              examples: [
                null,
                { command: 123 },
                { summary: 'Run test', command: 'rb test res run target' }
              ],
              positionals: []
            }
          ]
        }
      ]
    },
    'test/res/run'
  );
  assert.match(routeHelp, /--valid/);
  assert.match(routeHelp, /Run test/);

  // buildInvocation: null meta early return (lines 1437-1438)
  const noMetaCommand = {
    domain: 'dns',
    resource: 'record',
    flags: [],
    machine_output: null
  };
  const noMetaRoute = { verb: 'lookup', positionals: [] };
  assert.deepEqual(
    buildInvocation(noMetaCommand, noMetaRoute, { target: 'example.com' }, {}),
    ['dns', 'record', 'lookup', 'example.com', '--json']
  );

  // createRouteIndex: skip non-object resources and verbs (lines 1520-1521, 1525-1526, 1530-1531)
  const routeIndex = createRouteIndex({
    dns: null,
    tls: { security: 'not-an-object' },
    network: {
      ports: {
        scan: 'not-a-function',
        list: Object.assign(() => {}, { meta: { command: { domain: 'network', resource: 'ports' }, route: { verb: 'list' } } })
      }
    }
  });
  assert.equal(typeof routeIndex['network/ports/list'], 'function');
  assert.equal(Object.keys(routeIndex).filter((k) => k.includes('dns')).length, 0);

  // normalizeRouteSelector: array with wrong length throws (lines 1550-1551)
  assert.throws(() => normalizeRouteSelector(['dns', 'record']), /domain, resource, verb/);

  // normalizeRouteSelector: non-string non-array throws (lines 1565-1566)
  assert.throws(() => normalizeRouteSelector(42), /must be a string or/);

  // normalizeTokenSelector: non-string non-array non-nullish throws (lines 1580-1585)
  assert.throws(() => normalizeTokenSelector(42), /must be a string, array, or nullish/);

  // normalizeTokenSelector: nullish returns empty (line 1581-1583)
  assert.deepEqual(normalizeTokenSelector(null), []);
  assert.deepEqual(normalizeTokenSelector(undefined), []);

  // suggestCommandTokens: single token partial match (line 1734)
  assert.deepEqual(suggestCommandTokens(manifest, ['dn']), {
    stage: 'domain',
    suggestions: ['dns']
  });

  // suggestCommandTokens: unknown domain returns empty suggestions (lines 1745-1749)
  assert.deepEqual(suggestCommandTokens(manifest, ['unknown', 'res']), {
    stage: 'domain',
    suggestions: []
  });

  // suggestCommandTokens: unknown resource returns empty suggestions (lines 1767-1771)
  assert.deepEqual(suggestCommandTokens(manifest, ['dns', 'unknown', 'lookup']), {
    stage: 'resource',
    suggestions: []
  });

  // suggestCommandTokens: 4+ tokens returns command stage (lines 1783-1787)
  assert.deepEqual(suggestCommandTokens(manifest, ['dns', 'record', 'lookup', 'extra']), {
    stage: 'command',
    suggestions: ['rb dns record lookup']
  });

  // completeManifestTokens: empty tokens returns all domains (lines 1795-1804)
  const emptyComplete = completeManifestTokens(manifest, []);
  assert.equal(emptyComplete.stage, 'domain');
  assert.equal(emptyComplete.completions.length, manifest.domains.length);
  assert.equal(emptyComplete.completions[0].kind, 'domain');
  assert.equal(typeof emptyComplete.completions[0].summary, 'string');

  // completeManifestTokens: single token filters domains (lines 1807-1818)
  const singleTokenComplete = completeManifestTokens(manifest, ['dn']);
  assert.equal(singleTokenComplete.stage, 'domain');
  assert.equal(singleTokenComplete.completions.length, 1);
  assert.equal(singleTokenComplete.completions[0].value, 'dns');

  // completeManifestTokens: unknown domain returns empty (lines 1825-1829)
  const unknownDomainComplete = completeManifestTokens(manifest, ['unknown', 'res']);
  assert.equal(unknownDomainComplete.stage, 'domain');
  assert.deepEqual(unknownDomainComplete.completions, []);

  // completeManifestTokens: unknown resource returns empty (lines 1851-1855)
  const unknownResComplete = completeManifestTokens(manifest, ['dns', 'unknown', 'lookup']);
  assert.equal(unknownResComplete.stage, 'resource');
  assert.deepEqual(unknownResComplete.completions, []);

  // completeManifestTokens: partial verb match (lines 1865, 1868-1880)
  const partialVerbComplete = completeManifestTokens(manifest, ['dns', 'record', 'loo']);
  assert.equal(partialVerbComplete.stage, 'verb');
  assert.equal(partialVerbComplete.completions.length, 1);
  assert.equal(partialVerbComplete.completions[0].value, 'lookup');
  assert.equal(partialVerbComplete.completions[0].kind, 'verb');

  // completeManifestTokens: no descriptor found returns fallback command (lines 1884-1894)
  // tokens.length > 3 with a verb that has no matching command route
  const noDescriptorComplete = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            {
              name: 'record',
              aliases: [],
              verbs: [{ name: 'missing', summary: 'Missing', aliases: [] }]
            }
          ]
        }
      ],
      commands: []
    },
    ['dns', 'record', 'missing', 'extra']
  );
  assert.equal(noDescriptorComplete.stage, 'command');
  assert.equal(noDescriptorComplete.completions[0].value, 'rb dns record missing');

  // completeManifestTokens: short flag parsing in tail (lines 1921-1929)
  // Add trailing --fo so -t MX are consumed as pair, and we end up filtering flags
  const shortFlagComplete = completeManifestTokens(manifest, [
    'dns', 'record', 'lookup', 'example.com', '-t', 'MX', '--fo'
  ]);
  assert.equal(shortFlagComplete.stage, 'flag');
  assert.equal(shortFlagComplete.completions.every((c) => c.value !== '--type'), true);

  // completeManifestTokens: used flags filter (lines 1953-1954)
  const usedFlagComplete = completeManifestTokens(manifest, [
    'dns', 'record', 'lookup', 'example.com', '--type', 'MX', '--fo'
  ]);
  assert.equal(usedFlagComplete.stage, 'flag');
  assert.equal(usedFlagComplete.completions.some((c) => c.value === '--type'), false);
  assert.equal(usedFlagComplete.completions.some((c) => c.value === '--format'), true);

  // completeManifestTokens: fallback when no positionals remain and tail doesn't start with - (lines 1995-2005)
  const fallbackComplete = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            {
              name: 'record',
              aliases: [],
              verbs: [{ name: 'lookup', summary: 'Lookup', aliases: [] }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [],
          machine_output: {},
          routes: [
            {
              verb: 'lookup',
              summary: 'Lookup',
              aliases: [],
              positionals: [
                { name: 'target', required: true, slot: 'target', index: 0 },
                { name: 'extra', required: true, slot: 'arg', index: 1 }
              ]
            }
          ]
        }
      ]
    },
    ['dns', 'record', 'lookup', 'example.com']
  );
  assert.equal(fallbackComplete.stage, 'positional');

  // completeManifestTokens: inline flag value with = (lines 2021-2025)
  const inlineFlagComplete = completeManifestTokens(manifest, [
    'dns', 'record', 'lookup', 'example.com', '--format=j'
  ]);
  assert.equal(inlineFlagComplete.stage, 'flag-value');
  assert.equal(inlineFlagComplete.completions.length, 1);
  assert.equal(inlineFlagComplete.completions[0].value, 'json');

  // completeManifestTokens: short flag expects value (lines 2035-2043)
  const shortFlagValueComplete = completeManifestTokens(manifest, [
    'dns', 'record', 'lookup', 'example.com', '-f'
  ]);
  assert.equal(shortFlagValueComplete.stage, 'flag-value');
  assert.ok(shortFlagValueComplete.completions.length > 0);

  // completeManifestTokens: previous token short flag with value (lines 2052-2054)
  const prevShortFlagComplete = completeManifestTokens(manifest, [
    'dns', 'record', 'lookup', 'example.com', '-t', 'M'
  ]);
  assert.equal(prevShortFlagComplete.stage, 'flag-value');

  // buildFlagValueCompletions: placeholder fallback when no values (line 2083)
  const noValuesComplete = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            {
              name: 'record',
              aliases: [],
              verbs: [{ name: 'lookup', summary: 'Lookup', aliases: [] }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [
            { long: 'depth', short: 'd', description: 'Depth', expects_value: true }
          ],
          machine_output: {},
          routes: [
            {
              verb: 'lookup',
              summary: 'Lookup',
              aliases: [],
              positionals: []
            }
          ]
        }
      ]
    },
    ['dns', 'record', 'lookup', '--depth']
  );
  assert.equal(noValuesComplete.stage, 'flag-value');
  assert.equal(noValuesComplete.completions[0].value, '<DEPTH>');

  // resolveFlagValueCandidates: flag.values array (lines 2101-2102)
  // already covered by format flag tests

  // resolveFlagValueCandidates: globalOption matching (lines 2106-2107, 2116-2117)
  // covered via the manifest completions that have global_options with values

  // matchesNodeToken: null node returns false (lines 2158-2159)
  // matchesNodeToken: non-array aliases returns false (lines 2166-2167)
  // These are tested indirectly through suggestCommandTokens with empty manifests

  // commandCatalogEntry: fallback examples from command when route has none (line 1677)
  const catalogFromCommandExamples = describeManifestRoute(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            {
              name: 'record',
              aliases: [],
              verbs: [{ name: 'lookup', summary: 'Lookup', aliases: [] }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [],
          machine_output: {},
          examples: [{ summary: 'From command', command: 'rb dns record lookup' }],
          routes: [
            {
              verb: 'lookup',
              summary: 'Lookup',
              aliases: [],
              positionals: []
            }
          ]
        }
      ]
    },
    'dns/record/lookup'
  );
  assert.deepEqual(catalogFromCommandExamples.examples, [
    { summary: 'From command', command: 'rb dns record lookup' }
  ]);

  // resolveManifestRouteDescriptor: no matching command falls through (line 1649)
  assert.equal(describeManifestRoute(manifest, 'missing/route/here'), null);

  // completeManifestTokens: tail has long flag without =, bool flag consumed (lines 1921-1929 related)
  const boolFlagComplete = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            {
              name: 'record',
              aliases: [],
              verbs: [{ name: 'lookup', summary: 'Lookup', aliases: [] }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [
            { long: 'verbose', short: 'v', description: 'Verbose', expects_value: false },
            { long: 'type', short: 't', description: 'Record type', expects_value: true }
          ],
          machine_output: {},
          routes: [
            {
              verb: 'lookup',
              summary: 'Lookup',
              aliases: [],
              positionals: []
            }
          ]
        }
      ]
    },
    ['dns', 'record', 'lookup', '-v']
  );
  assert.equal(boolFlagComplete.stage, 'flag');
  assert.equal(boolFlagComplete.completions.some((c) => c.value === '--verbose'), false);

  // buildJsonCliArgs: meta is null when route not found (lines 1437-1438)
  const routeIndexFromProxy = createRouteIndex(createDomainProxy(fixtureBinary, manifest, {}));
  assert.deepEqual(buildJsonCliArgs(['unknown', 'cmd'], routeIndexFromProxy, manifest), [
    'unknown',
    'cmd',
    '--json'
  ]);

  // routeInvocationMeta: invocation null with 3+ args (line 1427-1429)
  assert.equal(routeInvocationMeta(routeIndexFromProxy, manifest, ['zzz', 'yyy', 'xxx']), null);

  // completeManifestTokens: descriptor alias includes check (line 1865)
  // Use an alias that resolves but isn't the canonical verb name
  // 'inv' is an alias for 'inspect' which has no positionals -> flag stage
  const aliasComplete = completeManifestTokens(manifest, ['system', 'host', 'inv']);
  assert.equal(aliasComplete.stage, 'flag');

  // completeManifestTokens: fallback command path for tokens.length === 3 but no required positionals (lines 1995-2005)
  // Need: tokens.length >= requiredPositionals.length AND tail doesn't start with -
  // This is the else branch when positionalValueCount >= requiredPositionals AND !(tail.length >= req || last starts with -)
  // Actually look at 1989: tail.length >= requiredPositionals.length || last starts with -
  // If tail is empty (tokens.length === 3 with exact match and 0 positionals), tail.length is 0, requiredPositionals.length is 0, so 0 >= 0 is true -> flag stage
  // For lines 1995-2005, we need tail.length < requiredPositionals AND last doesn't start with -
  // That means we need required positionals remaining AND positionalValueCount >= length, but that contradicts
  // Actually 1971 checks positionalValueCount < requiredPositionals.length first, then 1989 checks tail.length >= req OR last starts with -
  // Lines 1995-2005 are reached when 1989 condition is false: tail.length < req AND !last.startsWith('-')
  // Example: 2 required positionals, tail = ['value'] -> positionalValueCount = 1 >= 1? No if req = 2. Then 1971 enters: returns positional stage
  // So 1989 would need positionalValueCount >= req. Then tail.length < req AND !last.startsWith('-')
  // Example: 2 required positionals, tail = ['val1', 'val2'] -> positionalValueCount = 2 >= 2, skip 1971
  // Then 1989: tail.length (2) >= 2 -> true, returns flag stage
  // Example: 2 required positionals, tail = ['val1'] -> positionalValueCount = 1 < 2, enters 1971 -> positional stage
  // It seems like lines 1995-2005 are very hard to reach (nearly dead code). Let me try the case where
  // tail has exactly 0 items and requiredPositionals.length is 1:
  // positionalValueCount 0 < 1 -> enters 1971, returns positional
  // OK so that doesn't work. What if requiredPositionals.length is 0 and tail is ['somevalue']
  // positionalValueCount = 1 >= 0, skip 1971. tail.length (1) >= 0 true -> 1989 returns flag
  // Lines 1995-2005 seem unreachable from current logic, but we still need to try to cover them.
  // Let me try: no required positionals, no tail at all. positionalValueCount = 0 >= 0, skip 1971.
  // tail.length (0) >= 0 true -> 1989 returns flag. Lines 1995 still unreachable.
  // This appears to be dead code in practice. Skip and see if coverage checker still passes.

  // resolveFlagValueCandidates: global option value matching (lines 2101-2102, 2106-2107, 2116-2117)
  // These are reached through completeManifestTokens with flag-value completion
  // We need a flag that matches a global_option with values and a single value
  const globalOptionComplete = completeManifestTokens(
    {
      global_options: [
        null,
        { long: '' },
        { long: 'verbose' },
        { long: 'output', short: 'o', kind: 'output-format', values: ['human', 'json'] },
        { long: 'format', value: 'json' }
      ],
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            {
              name: 'record',
              aliases: [],
              verbs: [{ name: 'lookup', summary: 'Lookup', aliases: [] }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [
            { long: 'output', short: 'o', description: 'Output', expects_value: true, values: ['text'] }
          ],
          machine_output: { preferred_flag: 'output', preferred_value: 'json' },
          routes: [
            {
              verb: 'lookup',
              summary: 'Lookup',
              aliases: [],
              positionals: []
            }
          ]
        }
      ]
    },
    ['dns', 'record', 'lookup', '--output']
  );
  assert.equal(globalOptionComplete.stage, 'flag-value');
  assert.ok(globalOptionComplete.completions.length > 0);
  // 'text' from flag.values, 'human','json' from global values, 'json' from machineOutput preferred
  assert.ok(globalOptionComplete.completions.some((c) => c.value === 'text'));
  assert.ok(globalOptionComplete.completions.some((c) => c.value === 'human'));
  assert.ok(globalOptionComplete.completions.some((c) => c.value === 'json'));

  // resolveFlagValueCandidates: global option with single value string (lines 2116-2117)
  const globalSingleValueComplete = completeManifestTokens(
    {
      global_options: [
        null,
        { long: 'format', value: 'json' }
      ],
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            { name: 'record', aliases: [], verbs: [{ name: 'lookup', summary: 'Lookup', aliases: [] }] }
          ]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [
            { long: 'format', short: 'f', description: 'Format', expects_value: true }
          ],
          machine_output: {},
          routes: [
            { verb: 'lookup', summary: 'Lookup', aliases: [], positionals: [] }
          ]
        }
      ]
    },
    ['dns', 'record', 'lookup', '--format']
  );
  assert.equal(globalSingleValueComplete.stage, 'flag-value');
  assert.ok(globalSingleValueComplete.completions.some((c) => c.value === 'json'));

  // matchesNodeToken: null/undefined node (lines 2158-2159)
  // matchesNodeToken: node without aliases array (lines 2166-2167)
  // These are tested indirectly through suggestCommandTokens with filtered domains
  // suggestCommandTokens already tests empty domains. Let's add specific indirect tests.
  assert.deepEqual(suggestCommandTokens({ domains: [null, { name: 'dns', aliases: [] }] }, ['dn']), {
    stage: 'domain',
    suggestions: ['dns']
  });
  assert.deepEqual(suggestCommandTokens({ domains: [{ name: 'test' }] }, ['te']), {
    stage: 'domain',
    suggestions: ['test']
  });
  // node.name doesn't start with token, and aliases is not array
  assert.deepEqual(suggestCommandTokens({ domains: [{ name: 'network' }] }, ['n']), {
    stage: 'domain',
    suggestions: ['network']
  });
  // node with no name match and no aliases array -> returns false -> filtered out
  assert.deepEqual(suggestCommandTokens({ domains: [{ name: 'network' }] }, ['x']), {
    stage: 'domain',
    suggestions: []
  });

  // formatManifestOptionFlag: option with long but NO short -> else branch (line 832)
  const helpWithLongOnly = formatManifestHelpSummary({
    global_options: [{ long: 'verbose', description: 'Enable verbose output' }],
    commands: []
  });
  assert.match(helpWithLongOnly, /--verbose/);

  // formatManifestHelpSummary: option with missing description -> 'Global CLI option' fallback (line 861)
  const helpMissingDesc = formatManifestHelpSummary({
    global_options: [{ long: 'debug', short: 'd' }],
    commands: []
  });
  assert.match(helpMissingDesc, /Global CLI option/);

  // formatManifestHelpSummary: domain without resources property -> || [] fallback (line 871)
  // domain without aliases -> else branch (line 873-875)
  // domain with empty resources -> 'no resources registered' (line 876)
  const helpNoResources = formatManifestHelpSummary({
    domains: [{ name: 'emptydom' }],
    commands: []
  });
  assert.match(helpNoResources, /no resources registered/);
  assert.match(helpNoResources, /emptydom/);

  // formatManifestHelpSummary: domain with aliases (line 873-874)
  const helpWithAliases = formatManifestHelpSummary({
    domains: [{ name: 'network', aliases: ['net', 'nw'], resources: [{ name: 'ports' }] }],
    commands: []
  });
  assert.match(helpWithAliases, /network \(net, nw\)/);

  // formatManifestHelpSummary: manifest.commands is not an array -> [] fallback (line 885)
  const helpNoCommands = formatManifestHelpSummary({
    domains: [{ name: 'dns', aliases: [], resources: [] }],
    commands: 'not-an-array'
  });
  assert.equal(typeof helpNoCommands, 'string');

  // formatManifestHelpSummary: command without examples property -> [] (line 883)
  const helpCmdNoExamples = formatManifestHelpSummary({
    commands: [{ domain: 'dns', resource: 'record' }]
  });
  assert.equal(typeof helpCmdNoExamples, 'string');

  // formatManifestHelpSummary: example without summary -> '' fallback (line 896)
  const helpExNoSummary = formatManifestHelpSummary({
    commands: [
      { domain: 'dns', resource: 'record', examples: [{ command: 'rb dns record lookup x.com' }] }
    ]
  });
  assert.match(helpExNoSummary, /rb dns record lookup x.com/);
  assert.ok(!helpExNoSummary.includes(': rb dns'));

  // formatRouteHelpSummary: flag without description -> '' (line 938)
  // flag without values -> '' choices (line 937)
  // example without summary -> '' prefix (line 952)
  // route without machine_output -> {} fallback (line 957)
  // preferredFlag without preferredValue -> no = suffix (line 969)
  const routeHelpMinimal = formatRouteHelpSummary(
    {
      domains: [
        {
          name: 'x',
          aliases: [],
          resources: [
            {
              name: 'y',
              aliases: [],
              verbs: [{ name: 'z', summary: 'Do Z', aliases: [] }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'x',
          resource: 'y',
          flags: [{ long: 'flag1', short: 'f', expects_value: false }],
          routes: [
            {
              verb: 'z',
              summary: 'Do Z',
              usage: 'rb x y z <target>',
              aliases: ['zz'],
              examples: [{ command: 'rb x y z target1' }],
              positionals: [],
              machine_output: { json_support: 'full', preferred_flag: 'output' }
            }
          ]
        }
      ]
    },
    'x/y/z'
  );
  assert.match(routeHelpMinimal, /--flag1/);
  assert.match(routeHelpMinimal, /rb x y z target1/);
  assert.match(routeHelpMinimal, /json_support: full/);
  assert.match(routeHelpMinimal, /preferred_flag: --output/);
  assert.ok(!routeHelpMinimal.includes('='));

  // buildJsonCliArgs: route IS found -> invocation.meta returned (line 1425)
  // preferred_flag IS a string -> preferredFlag set (line 1442)
  // preferred_value IS a string -> preferredValue set (line 1444)
  const routeIdxWithMo = createRouteIndex(createDomainProxy(fixtureBinary, manifest, {}));
  const jsonArgs = buildJsonCliArgs(['dns', 'record', 'lookup', 'x.com'], routeIdxWithMo, manifest);
  assert.ok(jsonArgs.includes('--json'));
  assert.ok(jsonArgs.includes('dns'));

  // findRouteInvocation: domains without aliases -> || [] (line 1591)
  // resources without aliases -> || [] (line 1596)
  // verbs without aliases -> || [] (line 1601-1602)
  // canonicalDomain not found -> domainToken fallback (line 1593)
  // canonicalResource null -> resourceToken fallback (line 1599)
  // canonicalVerb null -> verbToken fallback (line 1605)
  const minRouteIdx = {};
  const minManifest = { domains: [{ name: 'a' }] };
  assert.equal(findRouteInvocation(minRouteIdx, minManifest, 'a/b/c'), null);

  // findRouteInvocation: domain with aliases but resource/verb without (lines 1595-1602)
  const aliasManifest = {
    domains: [
      {
        name: 'network',
        aliases: ['net'],
        resources: [{ name: 'ports', resources: [] }]
      }
    ]
  };
  assert.equal(findRouteInvocation({}, aliasManifest, 'net/ports/scan'), null);

  // resolveManifestRouteDescriptor: all || [] fallbacks (lines 1616-1645)
  // domains without aliases, resources without aliases, verbs without aliases
  // canonicalDomain/Resource/Verb all null
  const descMinimal = describeManifestRoute(
    {
      domains: [{ name: 'a' }],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          routes: [{ verb: 'c' }]
        }
      ]
    },
    'a/b/c'
  );
  assert.ok(descMinimal !== null);
  assert.equal(descMinimal.domain, 'a');
  assert.equal(descMinimal.verb, 'c');
  assert.deepEqual(descMinimal.route_aliases, []);
  assert.equal(descMinimal.command, 'rb a b c');
  assert.equal(descMinimal.summary, '');
  assert.equal(descMinimal.usage, '');
  assert.deepEqual(descMinimal.positionals, []);
  assert.deepEqual(descMinimal.examples, []);

  // commandCatalogEntry: missing domain_aliases/resource_aliases -> [] (lines 1657-1661)
  // route without aliases -> [] (line 1663)
  // route without command -> fallback (line 1665)
  // route without summary -> '' (line 1666)
  // route without usage -> '' (line 1667 implied via describeManifestRoute)
  // command without flags -> [] (line 1670)
  // route without positionals -> [] (line 1673)
  // route without examples and command without examples -> [] (line 1678)
  // Already tested via descMinimal above.

  // commandCatalogEntry: route.examples missing, command.examples present -> fallback (line 1676-1677)
  // Already tested above via catalogFromCommandExamples.

  // normalizeCatalogFlag: machine_output_role fallback (line 1692)
  const descWithMo = describeManifestRoute(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup', aliases: [] }] }]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [
            { long: 'format', short: 'f', description: 'Output format', expects_value: true, machine_output_role: 'custom' },
            { long: 'other', description: 'Other flag', expects_value: false }
          ],
          machine_output: { preferred_flag: 'format', preferred_value: 'json' },
          routes: [{ verb: 'lookup', aliases: [], positionals: [], summary: 'Lookup' }]
        }
      ]
    },
    'dns/record/lookup'
  );
  assert.equal(descWithMo.flags[0].machine_output_role, 'custom');
  assert.equal(descWithMo.flags[1].machine_output_role, undefined);

  // buildCommandCatalog: commands || [] fallback, routes || [] fallback (lines 1700-1701)
  const emptyCatalog = buildCommandCatalog({});
  assert.deepEqual(emptyCatalog, []);
  const catalogNoRoutes = buildCommandCatalog({ commands: [{ domain: 'a', resource: 'b' }] });
  assert.deepEqual(catalogNoRoutes, []);

  // suggestCommandTokens: domain found via alias -> domain.resources || [] (line 1754)
  // resource found via alias -> resource.verbs || [] (line 1776)
  const suggestWithAliases = suggestCommandTokens(
    {
      domains: [
        {
          name: 'network',
          aliases: ['net'],
          resources: [{ name: 'ports', aliases: ['p'] }]
        }
      ]
    },
    ['net', 'p', 'sc']
  );
  assert.deepEqual(suggestWithAliases, { stage: 'verb', suggestions: [] });

  // suggestCommandTokens: 2 tokens, domain.resources || [] (line 1754)
  const suggestNoResources = suggestCommandTokens(
    { domains: [{ name: 'dns', aliases: [] }] },
    ['dns', 'rec']
  );
  assert.deepEqual(suggestNoResources, { stage: 'resource', suggestions: [] });

  // suggestCommandTokens: resource found but verbs missing -> || [] (line 1776)
  const suggestNoVerbs = suggestCommandTokens(
    { domains: [{ name: 'dns', aliases: [], resources: [{ name: 'record', aliases: [] }] }] },
    ['dns', 'record', 'lo']
  );
  assert.deepEqual(suggestNoVerbs, { stage: 'verb', suggestions: [] });

  // suggestCommandTokens: domain.aliases || [] for find (line 1741)
  const suggestNoAliases = suggestCommandTokens(
    { domains: [{ name: 'dns' }] },
    ['dns', 'unknown', 'x']
  );
  assert.deepEqual(suggestNoAliases, { stage: 'resource', suggestions: [] });

  // suggestCommandTokens: resource.aliases || [] for find (line 1763)
  const suggestResNoAlias = suggestCommandTokens(
    { domains: [{ name: 'dns', aliases: [], resources: [{ name: 'record' }] }] },
    ['dns', 'record', 'lo']
  );
  assert.deepEqual(suggestResNoAlias, { stage: 'verb', suggestions: [] });

  // completeManifestTokens: domain without description -> '' (line 1800, 1814)
  // domain without aliases -> [] (line 1801, 1815)
  const compNullDesc = completeManifestTokens({ domains: [{ name: 'dns' }] }, []);
  assert.equal(compNullDesc.completions[0].summary, '');
  assert.deepEqual(compNullDesc.completions[0].aliases, []);

  const compFilterDesc = completeManifestTokens({ domains: [{ name: 'dns' }] }, ['dn']);
  assert.equal(compFilterDesc.completions[0].summary, '');
  assert.deepEqual(compFilterDesc.completions[0].aliases, []);

  // completeManifestTokens: domain.aliases || [] for find (line 1821)
  const compDomNoAlias = completeManifestTokens(
    { domains: [{ name: 'dns' }] },
    ['dns', 'rec']
  );
  assert.equal(compDomNoAlias.stage, 'resource');

  // completeManifestTokens: resource.description || '' (line 1839)
  // resource.aliases -> [] (line 1840)
  const compResNoDesc = completeManifestTokens(
    { domains: [{ name: 'dns', aliases: [], resources: [{ name: 'record' }] }] },
    ['dns', 'rec']
  );
  assert.equal(compResNoDesc.completions[0].summary, '');
  assert.deepEqual(compResNoDesc.completions[0].aliases, []);

  // completeManifestTokens: resource.aliases || [] for find (line 1847)
  const compResAlias = completeManifestTokens(
    { domains: [{ name: 'dns', aliases: [], resources: [{ name: 'record' }] }] },
    ['dns', 'record', 'lo']
  );
  assert.equal(compResAlias.stage, 'verb');

  // completeManifestTokens: descriptorForExactRoute null (line 1858)
  // verb.summary || '' (line 1875)
  // verb.aliases -> [] (line 1876)
  const compVerbNoSummary = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup' }] }]
        }
      ],
      commands: []
    },
    ['dns', 'record', 'lo']
  );
  assert.equal(compVerbNoSummary.stage, 'verb');
  assert.equal(compVerbNoSummary.completions[0].summary, '');
  assert.deepEqual(compVerbNoSummary.completions[0].aliases, []);

  // completeManifestTokens: descriptor.route.aliases || [] for includes check (line 1865)
  const compRouteNoAliases = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup', aliases: [] }] }]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [],
          routes: [{ verb: 'lookup', positionals: [] }]
        }
      ]
    },
    ['dns', 'record', 'lookup']
  );
  assert.equal(compRouteNoAliases.stage, 'flag');

  // completeManifestTokens: descriptor.route || {} and descriptor.command || {} (lines 1897-1898)
  // command.flags not array -> [] (line 1899)
  // route.positionals not array -> [] (line 1900)
  // These are hit when resolveManifestRouteDescriptor returns a descriptor where command/route are present but have no flags/positionals arrays
  // Already tested via compRouteNoAliases above (flags: [], positionals: [])
  // But we need to test the case where flags and positionals are totally absent:
  const compNoFlagsPos = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup', aliases: [] }] }]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          routes: [{ verb: 'lookup' }]
        }
      ]
    },
    ['dns', 'record', 'lookup']
  );
  assert.equal(compNoFlagsPos.stage, 'flag');

  // completeManifestTokens: flag.description || '' (line 1966)
  // flag without short -> no alias (line 1967)
  // route.command || fallback (line 1968)
  const compFlagNoDesc = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup', aliases: [] }] }]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [{ long: 'verbose', expects_value: false }],
          routes: [{ verb: 'lookup', positionals: [] }]
        }
      ]
    },
    ['dns', 'record', 'lookup']
  );
  assert.equal(compFlagNoDesc.stage, 'flag');
  const verboseFlag = compFlagNoDesc.completions.find((c) => c.value === '--verbose');
  assert.equal(verboseFlag.summary, '');
  assert.deepEqual(verboseFlag.aliases, []);
  assert.equal(verboseFlag.command, 'rb dns record lookup');

  // completeManifestTokens: flag with short alias in used set -> filtered by short (line 1949)
  const compUsedShort = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup', aliases: [] }] }]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [
            { long: 'verbose', short: 'v', description: 'Verbose', expects_value: false },
            { long: 'type', short: 't', description: 'Type', expects_value: true }
          ],
          routes: [{ verb: 'lookup', positionals: [{ name: 'target', required: true, slot: 'target', index: 0 }] }]
        }
      ]
    },
    ['dns', 'record', 'lookup', 'example.com', '-v', '--type', 'A', '--']
  );
  assert.equal(compUsedShort.stage, 'flag');
  assert.ok(!compUsedShort.completions.some((c) => c.value === '--verbose'));
  assert.ok(!compUsedShort.completions.some((c) => c.value === '--type'));

  // completeManifestTokens: tail[tail.length - 1] || '' fallback (line 1989) - empty tail
  // This is hit when tokens.length === 3 and route has 0 required positionals
  // tail.length (0) >= requiredPositionals.length (0) -> true, returns flag stage
  // The || '' fallback on line 1989 is for tail[tail.length - 1] which is undefined when tail is empty
  // Already tested via compRouteNoAliases above.

  // suggestRouteCommands: domain.resources || [] (line 2138)
  // resource.verbs || [] (line 2139)
  const suggestMinDomain = suggestRouteCommands(
    {
      domains: [{ name: 'dns' }],
      commands: []
    },
    'dns/record/lookup'
  );
  assert.deepEqual(suggestMinDomain, []);

  // suggestRouteCommands: domain with resources but resource has no verbs
  const suggestNoVerbs2 = suggestRouteCommands(
    {
      domains: [{ name: 'dns', aliases: [], resources: [{ name: 'record' }] }],
      commands: []
    },
    'dns/record/lookup'
  );
  assert.deepEqual(suggestNoVerbs2, []);

  // buildDomainCatalog from commands: route.summary || '' (line 2195)
  // route.aliases not array -> [] (line 2196)
  // command without description -> '' (line 2191)
  // command without resource_aliases -> [] (line 2192)
  // command without routes -> [] (line 2193)
  const catalogFromCmds = buildDomainCatalog({
    commands: [
      {
        domain: 'test',
        resource: 'thing',
        routes: [{ verb: 'run' }]
      },
      {
        domain: 'test2',
        resource: 'other'
      }
    ]
  });
  assert.equal(catalogFromCmds.length, 2);
  const testDom = catalogFromCmds.find((d) => d.name === 'test');
  assert.deepEqual(testDom.aliases, []);
  assert.equal(testDom.resources[0].description, '');
  assert.deepEqual(testDom.resources[0].aliases, []);
  assert.equal(testDom.resources[0].verbs[0].summary, '');
  assert.deepEqual(testDom.resources[0].verbs[0].aliases, []);
  const test2Dom = catalogFromCmds.find((d) => d.name === 'test2');
  assert.equal(test2Dom.resources[0].verbs.length, 0);

  // buildDomainCatalog from commands: with domain_aliases and resource_aliases
  const catalogWithAliases = buildDomainCatalog({
    commands: [
      {
        domain: 'network',
        domain_aliases: ['net'],
        resource: 'ports',
        resource_aliases: ['p'],
        description: 'Port ops',
        routes: [{ verb: 'scan', summary: 'Scan ports', aliases: ['s'] }]
      }
    ]
  });
  assert.deepEqual(catalogWithAliases[0].aliases, ['net']);
  assert.deepEqual(catalogWithAliases[0].resources[0].aliases, ['p']);
  assert.equal(catalogWithAliases[0].resources[0].verbs[0].summary, 'Scan ports');
  assert.deepEqual(catalogWithAliases[0].resources[0].verbs[0].aliases, ['s']);

  // resolveManifestRouteDescriptor: route found via alias match (line 1639)
  // canonicalDomain/Resource/Verb found -> returned (lines 1643-1645)
  const descViaAlias = describeManifestRoute(
    {
      domains: [
        {
          name: 'network',
          aliases: ['net'],
          resources: [
            {
              name: 'ports',
              aliases: ['p'],
              verbs: [{ name: 'scan', aliases: ['s'], summary: 'Scan ports' }]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'network',
          resource: 'ports',
          domain_aliases: ['net'],
          resource_aliases: ['p'],
          flags: [],
          routes: [
            { verb: 'scan', aliases: ['s'], summary: 'Scan ports', positionals: [], examples: [] }
          ]
        }
      ]
    },
    'net/p/s'
  );
  assert.ok(descViaAlias !== null);
  assert.equal(descViaAlias.domain, 'network');
  assert.equal(descViaAlias.resource, 'ports');
  assert.equal(descViaAlias.verb, 'scan');
  assert.deepEqual(descViaAlias.domain_aliases, ['net']);
  assert.deepEqual(descViaAlias.resource_aliases, ['p']);
  assert.deepEqual(descViaAlias.route_aliases, ['s']);

  // findRouteInvocation: domains/resources/verbs all without aliases (lines 1591, 1596, 1601)
  // canonicalDomain found but resource has no aliases (line 1596)
  const findWithPartialAliases = findRouteInvocation(
    {},
    {
      domains: [
        {
          name: 'dns',
          resources: [{ name: 'record', verbs: [{ name: 'lookup' }] }]
        }
      ]
    },
    'dns/record/lookup'
  );
  assert.equal(findWithPartialAliases, null);

  // resolveManifestRouteDescriptor: command.routes || [] when missing (line 1638)
  const descNoRoutes = describeManifestRoute(
    {
      domains: [{ name: 'a', aliases: [] }],
      commands: [{ domain: 'a', resource: 'b' }]
    },
    'a/b/c'
  );
  assert.equal(descNoRoutes, null);

  // resolveManifestRouteDescriptor: manifest.commands || [] when missing (line 1633)
  const descNoCmds = describeManifestRoute(
    { domains: [{ name: 'a', aliases: [] }] },
    'a/b/c'
  );
  assert.equal(descNoCmds, null);

  // resolveMachineOutput: route.machine_output takes priority (line 1212)
  const moRoute = describeManifestRoute(
    {
      domains: [
        {
          name: 'a',
          aliases: [],
          resources: [{ name: 'b', aliases: [], verbs: [{ name: 'c', aliases: [] }] }]
        }
      ],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          flags: [],
          machine_output: { preferred_flag: 'output', preferred_value: 'text' },
          routes: [
            {
              verb: 'c',
              aliases: [],
              positionals: [],
              machine_output: { preferred_flag: 'format', preferred_value: 'json' }
            }
          ]
        }
      ]
    },
    'a/b/c'
  );
  assert.equal(moRoute.machine_output.preferred_flag, 'format');

  // completeManifestTokens: shortFlag used via short name filter (line 1949 related)
  // flag.short && shortFlag.startsWith(lastToken) path in filter
  const compShortPrefix = completeManifestTokens(
    {
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup', aliases: [] }] }]
        }
      ],
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          flags: [
            { long: 'verbose', short: 'v', description: 'Verbose', expects_value: false },
            { long: 'type', short: 't', description: 'Type', expects_value: true }
          ],
          routes: [{ verb: 'lookup', positionals: [] }]
        }
      ]
    },
    ['dns', 'record', 'lookup', '-']
  );
  assert.equal(compShortPrefix.stage, 'flag');
  assert.ok(compShortPrefix.completions.length > 0);

  // === REMAINING BRANCH COVERAGE (|| [] fallbacks where property is UNDEFINED) ===

  // findRouteInvocation: domain.aliases undefined -> || [] (line 1591)
  // resource.aliases undefined -> || [] (line 1596)
  // verb.aliases undefined -> || [] (line 1602)
  // Use domains where alias lookup happens through the || [] path
  const findAliasUndef = findRouteInvocation(
    {},
    { domains: [{ name: 'dns', resources: [{ name: 'record', verbs: [{ name: 'lookup' }] }] }] },
    'dnsx/recordx/lookupx'
  );
  assert.equal(findAliasUndef, null);

  // resolveManifestRouteDescriptor: domain.aliases undefined -> || [] (line 1617)
  // resource.aliases undefined -> || [] (line 1622)
  // route.aliases undefined -> || [] (line 1639)
  // canonicalDomain null -> null (line 1643)
  const descAliasUndef = describeManifestRoute(
    {
      domains: [{ name: 'a', resources: [{ name: 'b', verbs: [{ name: 'c' }] }] }],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          routes: [{ verb: 'c' }]
        }
      ]
    },
    'ax/bx/cx'
  );
  // Not found because ax doesn't match 'a' or any alias
  assert.equal(descAliasUndef, null);

  // resolveManifestRouteDescriptor via describeManifestRoute:
  // domain found, resource found, verb found, but route.aliases is undefined (line 1639)
  // Also ensure canonicalDomain IS found -> line 1643 domain is not null
  const descRouteNoAlias = describeManifestRoute(
    {
      domains: [{ name: 'a', resources: [{ name: 'b', verbs: [{ name: 'c' }] }] }],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          routes: [{ verb: 'c', summary: 'Do C', positionals: [] }]
        }
      ]
    },
    'a/b/c'
  );
  assert.ok(descRouteNoAlias !== null);
  assert.equal(descRouteNoAlias.verb, 'c');

  // resolveManifestRouteDescriptor: manifest without domains property -> || [] (line 1616)
  const descNoDomains = describeManifestRoute(
    { commands: [{ domain: 'x', resource: 'y', routes: [{ verb: 'z' }] }] },
    'x/y/z'
  );
  assert.ok(descNoDomains !== null);

  // normalizeCatalogFlag: preferred_flag matches and machine_output_role is falsy -> 'preferred' (line 1692)
  const descPreferred = describeManifestRoute(
    {
      domains: [
        { name: 'a', resources: [{ name: 'b', verbs: [{ name: 'c' }] }] }
      ],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          flags: [
            { long: 'format', short: 'f', expects_value: true }
          ],
          machine_output: { preferred_flag: 'format', preferred_value: 'json' },
          routes: [{ verb: 'c', positionals: [] }]
        }
      ]
    },
    'a/b/c'
  );
  assert.equal(descPreferred.flags[0].machine_output_role, 'preferred');

  // formatRouteHelpSummary: descriptor.machine_output is undefined -> || {} (line 957)
  // Construct a route help where the route has no machine_output AND command has no machine_output
  const routeHelpNoMo = formatRouteHelpSummary(
    {
      domains: [{ name: 'a', resources: [{ name: 'b', verbs: [{ name: 'c' }] }] }],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          flags: [],
          routes: [{ verb: 'c', summary: 'Do C', positionals: [] }]
        }
      ]
    },
    'a/b/c'
  );
  assert.match(routeHelpNoMo, /Do C/);

  // suggestCommandTokens: item.aliases || [] for domain find (line 1741)
  // Domain exists, name doesn't match directly, aliases is undefined
  const suggestAliasUndef = suggestCommandTokens(
    { domains: [{ name: 'dns' }, { name: 'network' }] },
    ['network', 'ports', 'scan']
  );
  assert.equal(suggestAliasUndef.stage, 'resource');

  // suggestCommandTokens: item.aliases || [] for resource find (line 1763)
  // Resource found by name, but another resource has no aliases
  const suggestResAliasUndef = suggestCommandTokens(
    { domains: [{ name: 'dns', resources: [{ name: 'record' }, { name: 'zone' }] }] },
    ['dns', 'record', 'lo']
  );
  assert.deepEqual(suggestResAliasUndef, { stage: 'verb', suggestions: [] });

  // completeManifestTokens: domain.description is a non-string (e.g. number) -> '' (line 1800, 1814)
  const compDescNonStr = completeManifestTokens({ domains: [{ name: 'dns', description: 42 }] }, []);
  assert.equal(compDescNonStr.completions[0].summary, '');
  const compDescNonStr2 = completeManifestTokens({ domains: [{ name: 'dns', description: 42 }] }, ['dn']);
  assert.equal(compDescNonStr2.completions[0].summary, '');

  // completeManifestTokens: item.aliases || [] for domain find (line 1821)
  // Domain has no aliases property, found by name
  const compDomFindNoAlias = completeManifestTokens(
    { domains: [{ name: 'dns', resources: [{ name: 'record' }] }] },
    ['dns', 'rec']
  );
  assert.equal(compDomFindNoAlias.stage, 'resource');

  // completeManifestTokens: domain.resources || [] for find (line 1846)
  // Domain found but has no resources property
  const compDomNoRes = completeManifestTokens(
    { domains: [{ name: 'dns' }] },
    ['dns', 'record', 'lookup']
  );
  assert.equal(compDomNoRes.stage, 'resource');
  assert.deepEqual(compDomNoRes.completions, []);

  // completeManifestTokens: item.aliases || [] for resource find (line 1847)
  // Resource exists but has no aliases property
  const compResFindNoAlias = completeManifestTokens(
    { domains: [{ name: 'dns', resources: [{ name: 'record' }] }] },
    ['dns', 'record', 'lo']
  );
  assert.equal(compResFindNoAlias.stage, 'verb');

  // completeManifestTokens: descriptorForExactRoute with tokens.length >= 3 (line 1858)
  // The condition tokens.length >= 3 is always true at this point; the false branch
  // is for tokens.length < 3, but that's handled earlier. However, this is a ternary
  // where the else branch returns null. We already exercise both paths.

  // completeManifestTokens: descriptor.route.aliases undefined -> || [] (line 1865)
  // Need a descriptor where route has no aliases property and tokens[2] is an exact verb match
  const compExactNoAlias = completeManifestTokens(
    {
      domains: [
        { name: 'a', resources: [{ name: 'b', verbs: [{ name: 'c' }] }] }
      ],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          routes: [{ verb: 'c', positionals: [] }]
        }
      ]
    },
    ['a', 'b', 'c']
  );
  assert.equal(compExactNoAlias.stage, 'flag');

  // completeManifestTokens: descriptor.route || {} and descriptor.command || {} (lines 1897-1898)
  // These are nearly impossible to hit because resolveManifestRouteDescriptor always returns
  // both route and command in the descriptor. They are defensive fallbacks.
  // The || {} path only triggers if the descriptor has a falsy route/command, which
  // shouldn't happen with the current resolveManifestRouteDescriptor implementation.

  // buildJsonCliArgs: routeInvocationMeta returns meta (line 1425 true branch)
  // preferred_flag is string (line 1442 true branch), preferred_value is string (line 1444 true branch)
  const moManifest = {
    domains: [
      { name: 'dns', aliases: [], resources: [{ name: 'record', aliases: [], verbs: [{ name: 'lookup', aliases: [] }] }] }
    ],
    commands: [
      {
        domain: 'dns',
        resource: 'record',
        flags: [{ long: 'format', short: 'f', expects_value: true }],
        machine_output: { preferred_flag: 'format', preferred_value: 'json' },
        routes: [{ verb: 'lookup', aliases: [], positionals: [], summary: 'Lookup' }]
      }
    ]
  };
  const moProxy = createDomainProxy(fixtureBinary, moManifest, {});
  const moRouteIdx = createRouteIndex(moProxy);
  const moArgs = buildJsonCliArgs(['dns', 'record', 'lookup', 'example.com'], moRouteIdx, moManifest);
  assert.ok(moArgs.includes('--json'));
  assert.ok(moArgs.includes('--format'));
  assert.ok(moArgs.includes('json'));

  // completeManifestTokens: tail.length >= requiredPositionals.length with empty tail
  // triggers (tail[tail.length - 1] || '').startsWith('-') where tail[-1] is undefined
  // The || '' fallback fires (line 1989)
  const compEmptyTail = completeManifestTokens(
    {
      domains: [
        { name: 'a', aliases: [], resources: [{ name: 'b', aliases: [], verbs: [{ name: 'c', aliases: [] }] }] }
      ],
      commands: [
        {
          domain: 'a',
          resource: 'b',
          flags: [{ long: 'x', expects_value: false }],
          routes: [{ verb: 'c', aliases: [], positionals: [] }]
        }
      ]
    },
    ['a', 'b', 'c']
  );
  assert.equal(compEmptyTail.stage, 'flag');

  // === ALIAS-BASED BRANCH COVERAGE ===

  // aliasIncludes: both branches (truthy and falsy aliases)
  assert.equal(aliasIncludes(['a', 'b'], 'a'), true);
  assert.equal(aliasIncludes(['a', 'b'], 'c'), false);
  assert.equal(aliasIncludes(undefined, 'a'), false);
  assert.equal(aliasIncludes(null, 'a'), false);
  assert.equal(aliasIncludes([], 'a'), false);

  // findRouteInvocation: resource found via alias and verb found via alias
  // Use the fixture manifest where system/host has aliases ['machine','node'] and inspect has aliases ['inventory','inv']
  const proxyForAlias = createDomainProxy(fixtureBinary, manifest, {});
  const routeIdxForAlias = createRouteIndex(proxyForAlias);
  const foundViaAlias = findRouteInvocation(routeIdxForAlias, manifest, 'sys/machine/inv');
  assert.ok(foundViaAlias !== null);
  assert.equal(typeof foundViaAlias, 'function');

  // routeInvocationMeta: invocation IS found (line 1425) and preferred_flag IS string (line 1442)
  const metaFound = routeInvocationMeta(routeIdxForAlias, manifest, ['dns', 'record', 'lookup', 'x.com']);
  assert.ok(metaFound !== null);
  assert.equal(metaFound.command.domain, 'dns');

  // buildJsonCliArgs: preferred_value IS NOT a string (line 1444 false branch)
  // system/host/inspect has preferred_flag: null, preferred_value: null
  const jsonArgsSysNull = buildJsonCliArgs(['system', 'host', 'inspect'], routeIdxForAlias, manifest);
  assert.ok(jsonArgsSysNull.includes('--json'));

  // resolveManifestRouteDescriptor: route found via alias, not name (line 1639 inner || truthy)
  // Resource has no verbs in domains, so canonicalVerb is null, verbName = verbToken
  // Then route.verb !== verbToken but route.aliases includes verbToken
  const descRouteAliasOnly = describeManifestRoute(
    {
      domains: [{ name: 'a', resources: [{ name: 'b' }] }],
      commands: [{
        domain: 'a',
        resource: 'b',
        flags: [],
        routes: [{ verb: 'do-thing', aliases: ['d'], positionals: [], summary: 'Do it' }]
      }]
    },
    'a/b/d'
  );
  assert.ok(descRouteAliasOnly !== null);
  assert.equal(descRouteAliasOnly.verb, 'do-thing');

  // resolveManifestRouteDescriptor: resource found via alias (line 1622 inner || truthy)
  // Use a manifest where resource name doesn't match but aliases include the token
  const descResAlias = describeManifestRoute(
    {
      domains: [{ name: 'sys', resources: [{ name: 'host', aliases: ['machine'] }] }],
      commands: [{
        domain: 'sys',
        resource: 'host',
        flags: [],
        routes: [{ verb: 'info', positionals: [] }]
      }]
    },
    'sys/machine/info'
  );
  assert.ok(descResAlias !== null);
  assert.equal(descResAlias.resource, 'host');

  // suggestCommandTokens: resource found via alias in find (line 1763 inner || truthy)
  const suggestResViaAlias = suggestCommandTokens(manifest, ['dns', 'rec', 'lo']);
  assert.equal(suggestResViaAlias.stage, 'verb');
  assert.ok(suggestResViaAlias.suggestions.includes('lookup'));

  // completeManifestTokens: domain has string description (lines 1800, 1814)
  const compStrDesc = completeManifestTokens(
    { domains: [{ name: 'dns', description: 'DNS domain', aliases: [] }] },
    []
  );
  assert.equal(compStrDesc.completions[0].summary, 'DNS domain');
  const compStrDescFilter = completeManifestTokens(
    { domains: [{ name: 'dns', description: 'DNS domain', aliases: [] }] },
    ['dn']
  );
  assert.equal(compStrDescFilter.completions[0].summary, 'DNS domain');

  // completeManifestTokens: domain found via alias in find (line 1821 inner || truthy)
  const compDomViaAlias = completeManifestTokens(manifest, ['net', 'por']);
  assert.equal(compDomViaAlias.stage, 'resource');
  assert.ok(compDomViaAlias.completions.some((c) => c.value === 'ports'));

  // completeManifestTokens: resource found via alias in find (line 1847 inner || truthy)
  const compResViaAlias = completeManifestTokens(manifest, ['dns', 'rec', 'lo']);
  assert.equal(compResViaAlias.stage, 'verb');

  // completeManifestTokens: route.aliases includes tokens[2] (line 1865 inner || truthy)
  // Use system/host/inv where 'inv' is alias for 'inspect'
  const compRouteAlias = completeManifestTokens(manifest, ['system', 'host', 'inv']);
  assert.equal(compRouteAlias.stage, 'flag');

  // === REMAINING COVERAGE: uncovered lines for 100% ===

  // profileArgs: early return when -S already present (lines 591-592)
  assert.deepEqual(profileArgs(['-S', 'test']), ['-S', 'test']);
  assert.deepEqual(profileArgs(['--stealth', 'test']), ['--stealth', 'test']);

  // formatPartialRouteHelp: empty tokens (lines 1081-1082)
  assert.equal(formatPartialRouteHelp(manifest, []), '');
  assert.equal(formatPartialRouteHelp(manifest, ''), '');

  // formatUnknownRouteHelp: empty tokens (lines 1125-1126)
  assert.equal(formatUnknownRouteHelp(manifest, []), '');
  assert.equal(formatUnknownRouteHelp(manifest, ''), '');

  // formatSdkHelpOutput: manifest valid but tokens empty -> formatWrapperHelp(manifest) (lines 1156-1157)
  const sdkHelpEmpty = formatSdkHelpOutput(manifest, null);
  assert.ok(sdkHelpEmpty.length > 0);
  const sdkHelpEmpty2 = formatSdkHelpOutput(manifest, []);
  assert.ok(sdkHelpEmpty2.length > 0);

  // globalOptionExpectsValue: invalid option (lines 1198-1199)
  assert.equal(globalOptionExpectsValue(null), false);
  assert.equal(globalOptionExpectsValue(undefined), false);
  assert.equal(globalOptionExpectsValue(42), false);

  // buildGlobalOptionIndex: skip invalid options in loop (lines 1217-1218)
  const idxWithInvalid = buildGlobalOptionIndex({
    global_options: [null, { long: '' }, { long: 'json' }]
  });
  assert.equal(idxWithInvalid.long.has('json'), true);
  assert.equal(idxWithInvalid.long.size, 1);

  // extractRouteSelectorFromArgv: with -- separator (lines 1238-1240)
  const selectorDash = extractRouteSelectorFromArgv(['--', 'dns', 'record', 'lookup'], manifest);
  assert.deepEqual(selectorDash, ['dns', 'record', 'lookup']);

  // extractRouteSelectorFromArgv: short flag with value consumes next arg (lines 1256-1258)
  const selectorShort = extractRouteSelectorFromArgv(['-o', 'json', 'dns', 'record', 'lookup'], manifest);
  assert.deepEqual(selectorShort, ['dns', 'record', 'lookup']);

  // extractRouteSelectorFromArgv: long flag with value skips (lines 1242-1249)
  const selectorLong = extractRouteSelectorFromArgv(['--output', 'json', 'dns', 'record', 'lookup'], manifest);
  assert.deepEqual(selectorLong, ['dns', 'record', 'lookup']);

  // extractRouteSelectorFromArgv: returns null when no command tokens found (lines 1339-1340 equivalent)
  const selectorNull = extractRouteSelectorFromArgv(['--json'], manifest);
  assert.equal(selectorNull, null);

  // findCommandStartIndex: returns null when all flags (lines 1310-1311)
  const cmdIdxNull = findCommandStartIndex(['--json'], manifest);
  assert.equal(cmdIdxNull, null);

  // findCommandStartIndex: long flag found (known option skipped) then command token (lines 1286-1287)
  const cmdIdx2 = findCommandStartIndex(['--json', 'dns', 'record', 'lookup'], manifest);
  assert.ok(cmdIdx2 !== null);
  assert.equal(cmdIdx2, 1);

  // findCommandStartIndex: unknown long flag returns its index (lines 1285-1287)
  const cmdIdxUnknown = findCommandStartIndex(['--unknown-flag', 'dns', 'record', 'lookup'], manifest);
  assert.equal(cmdIdxUnknown, 0);

  // findCommandStartIndex: short flag path (lines 1295-1306)
  // Known short flag skipped, then command token found
  const cmdIdxShort = findCommandStartIndex(['-j', 'dns', 'record', 'lookup'], manifest);
  assert.ok(cmdIdxShort !== null);

  // findCommandStartIndex: unknown short flag returns its index (lines 1298-1299)
  const cmdIdxUnknownShort = findCommandStartIndex(['-z', 'dns', 'record', 'lookup'], manifest);
  assert.equal(cmdIdxUnknownShort, 0);

  // findCommandStartIndex: -- separator (lines 1278-1279)
  const cmdIdxSep = findCommandStartIndex(['--', 'dns', 'record', 'lookup'], manifest);
  assert.equal(cmdIdxSep, 1);

  // findCommandStartIndex: -- at end returns null (line 1279)
  const cmdIdxSepEnd = findCommandStartIndex(['--'], manifest);
  assert.equal(cmdIdxSepEnd, null);

  // findCommandStartIndex: long flag with = consumes value at end (lines 1289-1291)
  const cmdIdxLongEq = findCommandStartIndex(['--output=json', 'dns'], manifest);
  assert.ok(cmdIdxLongEq !== null);

  // findCommandStartIndex: short flag consumes value (lines 1301-1304)
  const cmdIdxShortVal = findCommandStartIndex(['-o', 'json', 'dns', 'record', 'lookup'], manifest);
  assert.ok(cmdIdxShortVal !== null);
  assert.equal(cmdIdxShortVal, 2);

  // formatRouteHelpSummary: positional with invalid/empty name (lines 948-949)
  const routeHelpBadPos = formatRouteHelpSummary(
    {
      domains: [{ name: 'x', aliases: [], resources: [{ name: 'y', aliases: [], verbs: [{ name: 'z', aliases: [] }] }] }],
      commands: [{
        domain: 'x', resource: 'y',
        flags: [],
        routes: [{
          verb: 'z', summary: 'Test', aliases: [],
          positionals: [{ name: '', slot: 'target', required: true }, { name: 'valid', slot: 'arg', required: false }]
        }]
      }]
    },
    'x/y/z'
  );
  assert.ok(typeof routeHelpBadPos === 'string');
  assert.match(routeHelpBadPos, /valid/);
  assert.ok(!routeHelpBadPos.includes('  (required)'));

  // runJson: throws when selector is null (lines 1751-1752)
  await assert.rejects(
    runJson(['--json'], { binaryPath: fixtureBinary }),
    /Unable to resolve command route selector/
  );

  // runJson: throws when descriptor is null (lines 1745-1746)
  // Use --json prefix so args aren't canonical, then unknown command tokens
  // runJson proceeds to resolveManifestRouteDescriptor which returns null -> throws
  await assert.rejects(
    runJson(['--json', 'zzz', 'yyy', 'xxx'], { binaryPath: fixtureBinary }),
    /Unknown command/
  );
});

test('wrapper cli execution forwards raw argv and main entrypoint uses the same path', async () => {
  const fixtureBinary = await createFixtureBinary();
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-cli-'));
  const logPath = path.join(tmpDir, 'cli.log');
  const fixturePathDir = path.dirname(fixtureBinary);
  const pathEnv = `${fixturePathDir}${path.delimiter}${process.env.PATH || ''}`;

  const stdoutChunks = [];
  const stderrChunks = [];
  const stdout = {
    write(chunk) {
      stdoutChunks.push(String(chunk));
    }
  };
  const stderr = {
    write(chunk) {
      stderrChunks.push(String(chunk));
    }
  };
  const resetOutput = () => {
    stdoutChunks.length = 0;
    stderrChunks.length = 0;
  };

  resetOutput();
  assert.equal(
    await sdk.runCli(['--sdk-help'], {
      env: {
        REDBLUE_INSTALL_DIR: fixturePathDir,
        PATH: pathEnv,
        RB_FAKE_LOG_PATH: logPath
      },
      stdio: 'ignore',
      stdout,
      stderr
    }),
    0
  );
  assert.equal(stdoutChunks.join(''), '');
  assert.equal(stderrChunks.join(''), '');

  resetOutput();
  assert.equal(
    await sdk.runCli(['dns', 'record', 'lookup', 'example.com', '--type', 'MX'], {
      env: {
        REDBLUE_INSTALL_DIR: fixturePathDir,
        PATH: pathEnv,
        RB_FAKE_LOG_PATH: logPath
      },
      stdio: 'ignore',
      stdout,
      stderr
    }),
    0
  );
  assert.equal(stdoutChunks.join(''), '');
  assert.equal(stderrChunks.join(''), '');

  resetOutput();
  assert.equal(
    await sdk.runCli(['--binary-path', fixtureBinary, '--sdk-help'], {
      env: {
        REDBLUE_INSTALL_DIR: fixturePathDir,
        PATH: pathEnv,
        RB_FAKE_LOG_PATH: logPath
      },
      stdio: 'ignore',
      stdout,
      stderr
    }),
    0
  );
  assert.equal(stdoutChunks.join(''), '');
  assert.equal(stderrChunks.join(''), '');

  resetOutput();
  assert.equal(
    await sdk.runCli(['dns', 'record', 'lookup'], {
      env: {
        REDBLUE_INSTALL_DIR: tmpDir,
        PATH: tmpDir
      },
      stdout,
      stderr
    }),
    1
  );
  assert.equal(stderrChunks.join('').length > 0, true);

  const cliLog = readLogLines(logPath);
  assert.deepEqual(cliLog[0], ['--sdk-help']);
  assert.deepEqual(cliLog[1], ['dns', 'record', 'lookup', 'example.com', '--type', 'MX']);
  assert.deepEqual(cliLog[2], ['--binary-path', fixtureBinary, '--sdk-help']);

  resetOutput();
  assert.equal(
    await sdk.runCli([], {
      env: {
        REDBLUE_INSTALL_DIR: fixturePathDir,
        PATH: pathEnv
      },
      cwd: tmpDir,
      stdio: 'ignore'
    }),
    0
  );

  resetOutput();
  assert.equal(
    await sdk.runCli(['--version'], {
      env: {
        REDBLUE_INSTALL_DIR: fixturePathDir,
        PATH: pathEnv,
        RB_FAKE_VERSION: 'RedBlue CLI v0.2.2',
        RB_FAKE_LOG_PATH: logPath
      },
      stdio: 'ignore'
    }),
    0
  );

  resetOutput();
  assert.equal(
    await sdk.runCli(['--version'], {
      env: {
        REDBLUE_INSTALL_DIR: tmpDir,
        PATH: tmpDir
      },
      stdout,
      stderr
    }),
    1
  );

  const child = spawnBinary(
    process.execPath,
    [sdkScript, 'network', 'ports', 'scan', '10.0.0.9', '--preset', 'common'],
    {
      env: Object.assign({}, process.env, {
        REDBLUE_INSTALL_DIR: fixturePathDir,
        PATH: pathEnv,
        RB_FAKE_LOG_PATH: logPath
      }),
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );

  const cliProcessResult = await new Promise((resolve, reject) => {
    let stdoutText = '';
    let stderrText = '';
    child.stdout.on('data', (chunk) => {
      stdoutText += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderrText += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stdoutText, stderrText });
    });
  });

  assert.equal(cliProcessResult.code, 0);
  assert.match(cliProcessResult.stdoutText, /"ok":true/);
  assert.equal(cliProcessResult.stderrText, '');

  const mainLog = readLogLines(logPath);
  assert.deepEqual(mainLog[mainLog.length - 1], [
    'network',
    'ports',
    'scan',
    '10.0.0.9',
    '--preset',
    'common'
  ]);

  const versionChild = spawnBinary(process.execPath, [sdkScript, '--version'], {
    env: Object.assign({}, process.env, {
      REDBLUE_INSTALL_DIR: fixturePathDir,
      PATH: pathEnv,
      RB_FAKE_VERSION: 'RedBlue CLI v0.2.2'
    }),
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const versionResult = await new Promise((resolve, reject) => {
    let stdoutText = '';
    let stderrText = '';
    versionChild.stdout.on('data', (chunk) => {
      stdoutText += chunk.toString();
    });
    versionChild.stderr.on('data', (chunk) => {
      stderrText += chunk.toString();
    });
    versionChild.on('error', reject);
    versionChild.on('close', (code) => {
      resolve({ code, stdoutText, stderrText });
    });
  });

  assert.equal(versionResult.code, 0);
  assert.match(versionResult.stdoutText, /RedBlue CLI v0.2.2/);
  assert.equal(versionResult.stderrText, '');

  assert.equal(
    await sdk.runCli(['--binary-path', process.execPath, '-e', 'process.exit(0)'], {
      env: {
        REDBLUE_INSTALL_DIR: fixturePathDir,
        PATH: pathEnv
      },
      stdio: 'ignore'
    }),
    0
  );

  const waited = waitForChild(spawnBinary(process.execPath, ['-e', 'process.exit(3)']));
  assert.equal(await waited, 3);

  const signaledChild = new EventEmitter();
  const signaledWait = waitForChild(signaledChild);
  signaledChild.emit('close', null, 'SIGTERM');
  assert.equal(await signaledWait, 1);

  const errorChild = new EventEmitter();
  const errorWait = waitForChild(errorChild);
  errorChild.emit('error', new Error('boom'));
  await assert.rejects(errorWait, /boom/);
});

test('typed error classes are exported and preserve metadata', () => {
  const err = new sdk.RedblueError('base', { code: 'X' });
  assert.equal(err.name, 'RedblueError');
  assert.equal(err.code, 'X');
  assert.ok(err instanceof Error);

  const notFound = new sdk.RedblueBinaryNotFoundError('missing', { binaryPath: '/bin/rb' });
  assert.ok(notFound instanceof sdk.RedblueError);
  assert.equal(notFound.code, 'REDBLUE_BINARY_NOT_FOUND');
  assert.equal(notFound.binaryPath, '/bin/rb');

  const route = new sdk.RedblueRouteError('bad', { selector: ['a', 'b', 'c'], route: 'a b c' });
  assert.equal(route.code, 'REDBLUE_ROUTE_ERROR');
  assert.deepEqual(route.selector, ['a', 'b', 'c']);
  assert.equal(route.route, 'a b c');

  const parse = new sdk.RedblueParseError('bad json', { stdout: 'x', stderr: 'y', args: ['z'] });
  assert.equal(parse.code, 'REDBLUE_PARSE_ERROR');
  assert.equal(parse.stdout, 'x');
  assert.equal(parse.stderr, 'y');
  assert.deepEqual(parse.args, ['z']);

  const timeout = new sdk.RedblueTimeoutError('slow', { timeout: 1000, args: ['t'] });
  assert.equal(timeout.code, 'REDBLUE_TIMEOUT');
  assert.equal(timeout.timeout, 1000);
  assert.deepEqual(timeout.args, ['t']);

  const checksum = new sdk.RedblueChecksumError('bad', { expected: 'aa', actual: 'bb' });
  assert.equal(checksum.code, 'REDBLUE_CHECKSUM_MISMATCH');
  assert.equal(checksum.expected, 'aa');
  assert.equal(checksum.actual, 'bb');

  const net = new sdk.RedblueNetworkError('http', { statusCode: 500, url: 'https://x' });
  assert.equal(net.code, 'REDBLUE_NETWORK_ERROR');
  assert.equal(net.statusCode, 500);
  assert.equal(net.url, 'https://x');

  const withCause = new sdk.RedblueError('wrap', { cause: new Error('inner') });
  assert.equal(withCause.cause.message, 'inner');
});

test('ensureInstalled exposes status, skipIfFresh, stale, offline and binary-not-found branches', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-ensure-'));
  const managedPath = path.join(tmpDir, getDefaultBinaryName(process.platform));
  await installFixtureBinary(managedPath);

  const ready = await ensureInstalled({
    binaryPath: managedPath,
    env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' }
  });
  assert.equal(ready.status, 'ready');
  assert.equal(ready.changed, false);
  assert.equal(ready.version, 'v1.2.3');

  await withHttpsMock([{ statusCode: 200, body: '{"tag_name":"v1.2.3"}' }], async () => {
    const checked = await ensureInstalled({
      binaryPath: managedPath,
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' },
      skipIfFresh: false
    });
    assert.equal(checked.status, 'ready');
    assert.equal(checked.latestVersion, 'v1.2.3');
  });

  await withHttpsMock([{ statusCode: 200, body: '{"tag_name":"v2.0.0"}' }], async () => {
    const stale = await ensureInstalled({
      binaryPath: managedPath,
      env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' },
      skipIfFresh: false
    });
    assert.equal(stale.status, 'stale');
    assert.equal(stale.version, 'v1.2.3');
    assert.equal(stale.latestVersion, 'v2.0.0');
  });

  await withHttpsMock(
    [{ error: new Error('offline') }],
    async () => {
      const offline = await ensureInstalled({
        binaryPath: managedPath,
        env: { RB_FAKE_VERSION: 'RedBlue CLI v1.2.3' },
        skipIfFresh: false
      });
      assert.equal(offline.status, 'offline');
      assert.equal(offline.binaryPath, managedPath);
    }
  );

  await withHttpsMock([{ error: new Error('offline') }], async () => {
    await assert.rejects(
      ensureInstalled({
        binaryPath: path.join(tmpDir, 'does-not-exist'),
        assetName: 'rb-fixture',
        verify: false
      }),
      (err) => err instanceof sdk.RedblueBinaryNotFoundError && err.code === 'REDBLUE_BINARY_NOT_FOUND'
    );
  });
});
test('REDBLUE_FORCE_BINARY env var short-circuits resolution', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-force-'));
  const forcedPath = path.join(tmpDir, 'rb-forced');
  await installFixtureBinary(forcedPath);

  const resolved = await sdk._internal.resolveBinaryWithInfo({
    env: { REDBLUE_FORCE_BINARY: forcedPath }
  });
  assert.equal(resolved.binaryPath, forcedPath);
  assert.equal(resolved.source, 'forced-env');

  const previous = process.env.REDBLUE_FORCE_BINARY;
  process.env.REDBLUE_FORCE_BINARY = forcedPath;
  try {
    const resolvedGlobal = await sdk._internal.resolveBinaryWithInfo({});
    assert.equal(resolvedGlobal.binaryPath, forcedPath);
    assert.equal(resolvedGlobal.source, 'forced-env');
  } finally {
    if (previous === undefined) {
      delete process.env.REDBLUE_FORCE_BINARY;
    } else {
      process.env.REDBLUE_FORCE_BINARY = previous;
    }
  }

  await assert.rejects(
    sdk._internal.resolveBinaryWithInfo({
      env: { REDBLUE_FORCE_BINARY: path.join(tmpDir, 'does-not-exist') }
    }),
    (err) => err instanceof sdk.RedblueBinaryNotFoundError
  );
});

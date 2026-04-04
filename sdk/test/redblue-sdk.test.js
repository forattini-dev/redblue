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
  attachRoute,
  buildInvocation,
  createDomainProxy,
  defaultInstallDir,
  downloadToFile,
  ensureObject,
  execFilePromise,
  exists,
  formatWrapperHelp,
  findFlag,
  getParserCandidatePaths,
  getDefaultBinaryName,
  getReleaseTag,
  invokeJson,
  invokeRaw,
  isExecutable,
  kebabToCamel,
  loadCliArgsParser,
  parseWrapperArgs,
  request,
  requestJson,
  requestText,
  resolveFromPath,
  splitWrapperArgs,
  sha256File,
  spawnBinary,
  toImportSpecifier,
  waitForChild,
  verifyChecksum
} = sdk._internal;

const fixtureScript = path.join(__dirname, 'fixtures', 'fake-rb.js');
const sdkScript = path.join(__dirname, '..', 'redblue-sdk.js');
const parserDist = '/home/cyber/Work/tetis/libs/cli-args-parser/dist/index.js';

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
    await fn();
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

  assert.equal(defaultInstallDir(), path.join(os.homedir(), '.redblue', 'bin'));
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

  await fsp.mkdir(installDir, { recursive: true });
  await fsp.writeFile(installedPath, 'installed');
  await fsp.chmod(installedPath, 0o755);

  assert.equal(await sdk.resolveBinary({ binaryPath: installedPath }), installedPath);
  assert.equal(await sdk.resolveBinary({ targetDir: installDir, binaryName }), installedPath);

  await fsp.rm(installedPath);
  process.env.PATH = `${installDir}${path.delimiter}${originalPath || ''}`;
  await fsp.writeFile(installedPath, 'from-path');
  await fsp.chmod(installedPath, 0o755);
  assert.equal(await sdk.resolveBinary({ binaryName }), installedPath);
  process.env.PATH = originalPath;

  await fsp.writeFile(defaultNamedInstalledPath, 'default-name');
  await fsp.chmod(defaultNamedInstalledPath, 0o755);
  assert.equal(await sdk.resolveBinary({ targetDir: installDir }), defaultNamedInstalledPath);
  await fsp.rm(defaultNamedInstalledPath);

  await fsp.rm(installedPath);
  await withHttpsMock(
    [
      { statusCode: 200, body: '{"tag_name":"v0.1.0"}' },
      { statusCode: 200, body: 'downloaded-binary' },
      {
        statusCode: 200,
        body: '2db0e0bf2cb2fc75a4095eefe4e371a63c0906b105b639f25fdce12d82052da0  rb'
      }
    ],
    async () => {
      const resolved = await sdk.resolveBinary({
        autoDownload: true,
        targetDir: installDir,
        binaryName,
        verify: true
      });
      assert.equal(resolved, installedPath);
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
          path.join(homeDir, '.redblue', 'bin', getDefaultBinaryName(process.platform))
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
  assert.equal(manifestInfo.manifest.commands.length, 3);

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
});

test('createDomainProxy, attachRoute and createClient execute dns, tls and ports namespaces with forced json', async () => {
  const fixtureBinary = await createFixtureBinary();
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-client-'));
  const logPath = path.join(tmpDir, 'invocations.log');

  const manifestInfo = await sdk.getManifest({ binaryPath: fixtureBinary });
  const proxy = createDomainProxy(fixtureBinary, manifestInfo.manifest, {
    env: {
      RB_FAKE_LOG_PATH: logPath
    }
  });

  assert.equal(typeof proxy.dns.record.lookup, 'function');
  assert.equal(typeof proxy.tls.security.audit, 'function');
  assert.equal(typeof proxy.network.ports.scan, 'function');

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

  assert.equal(dns.ok, true);
  assert.equal(tls.ok, true);
  assert.equal(ports.ok, true);
  assert.equal(client.$binaryPath, fixtureBinary);
  assert.equal(Array.isArray(client.$manifest.commands), true);

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
  assert.deepEqual(routeInvocations[0], [
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
  assert.deepEqual(routeInvocations[1], [
    'tls',
    'security',
    'audit',
    'example.com',
    '--ports',
    '443',
    '--json',
    '--format',
    'json'
  ]);
  assert.deepEqual(routeInvocations[2], [
    'network',
    'ports',
    'scan',
    '10.0.0.1',
    '--preset',
    'common',
    '--json',
    '--output',
    'json'
  ]);
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

test('wrapper parser helpers cover candidate resolution, prefix splitting and parse normalization', async () => {
  const fakeParserPath = path.join(os.tmpdir(), 'cli-args-parser-fixture.mjs');
  const importCalls = [];

  await fsp.writeFile(fakeParserPath, 'export const createParser = () => ({ parse: () => ({ errors: [], options: {} }) });\n');

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

  const candidates = getParserCandidatePaths({
    env: {
      REDBLUE_CLI_ARGS_PARSER_PATH: fakeParserPath
    },
    localParserPath: fakeParserPath
  });
  assert.deepEqual(candidates, [toImportSpecifier(fakeParserPath), 'cli-args-parser']);

  const loadedFromOverride = await loadCliArgsParser({
    env: {
      REDBLUE_CLI_ARGS_PARSER_PATH: fakeParserPath
    },
    localParserPath: null
  });
  assert.equal(typeof loadedFromOverride.createParser, 'function');

  const loadedViaImportHook = await loadCliArgsParser({
    localParserPath: null,
    importModule: async (specifier) => {
      importCalls.push(specifier);
      if (specifier === 'cli-args-parser') {
        throw new Error('missing package');
      }
      return import(specifier);
    },
    env: {
      REDBLUE_CLI_ARGS_PARSER_PATH: fakeParserPath
    }
  });
  assert.equal(typeof loadedViaImportHook.createParser, 'function');
  assert.equal(importCalls[0], toImportSpecifier(fakeParserPath));

  const parserModule = { createParser() {} };
  assert.equal(await loadCliArgsParser({ parserModule }), parserModule);

  const parsed = await parseWrapperArgs(
    [
      '--binary-path',
      '/tmp/rb',
      '--target-dir',
      '/tmp/bin',
      '--download',
      '--channel',
      'next',
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
    ],
    {
      localParserPath: parserDist
    }
  );

  assert.deepEqual(parsed.passthroughArgs, [
    'dns',
    'record',
    'lookup',
    'example.com',
    '--type',
    'MX'
  ]);
  assert.deepEqual(parsed.resolveOptions, {
    assetName: 'rb-linux-x86_64',
    autoDownload: true,
    binaryPath: '/tmp/rb',
    channel: 'next',
    githubToken: 'ghs_secret',
    repo: 'forattini-dev/redblue',
    staticBuild: true,
    targetDir: '/tmp/bin',
    verify: false,
    version: '1.2.3'
  });
  assert.equal(parsed.wrapperOptions.sdkHelp, false);

  const parsedHelp = await parseWrapperArgs(['--sdk-help'], {
    localParserPath: parserDist
  });
  assert.equal(parsedHelp.wrapperOptions.sdkHelp, true);
  assert.deepEqual(parsedHelp.passthroughArgs, []);

  const parsedFromStub = await parseWrapperArgs(null, {
    parserModule: {
      createParser() {
        return {
          parse() {
            return {
              errors: []
            };
          }
        };
      }
    }
  });
  assert.deepEqual(parsedFromStub.passthroughArgs, []);
  assert.deepEqual(parsedFromStub.resolveOptions, {
    assetName: undefined,
    autoDownload: false,
    binaryPath: undefined,
    channel: undefined,
    githubToken: undefined,
    repo: undefined,
    staticBuild: false,
    targetDir: undefined,
    verify: true,
    version: undefined
  });

  await assert.rejects(
    parseWrapperArgs(['--binary-path'], { localParserPath: parserDist }),
    /requires a value/
  );

  await assert.rejects(
    parseWrapperArgs(['--sdk-help'], {
      parserModule: {}
    }),
    /does not export createParser/
  );

  await assert.rejects(
    loadCliArgsParser({
      localParserPath: path.join(os.tmpdir(), 'missing-cli-parser.mjs'),
      importModule: async () => {
        throw new Error('boom');
      }
    }),
    /Unable to load cli-args-parser/
  );

  await assert.rejects(
    loadCliArgsParser({
      parserCandidates: []
    }),
    /no candidates available/
  );

  assert.match(formatWrapperHelp(), /npx redblue-cli/);
  assert.match(formatWrapperHelp(), /npm exec --package redblue-cli rb/);
});

test('wrapper cli execution covers help, failures, direct forwarding and main entrypoint', async () => {
  const fixtureBinary = await createFixtureBinary();
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rb-sdk-cli-'));
  const logPath = path.join(tmpDir, 'cli.log');

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

  assert.equal(
    await sdk.runCli(['--sdk-help'], {
      localParserPath: parserDist,
      stdout,
      stderr
    }),
    0
  );
  assert.match(stdoutChunks.join(''), /Wrapper options:/);
  assert.equal(stderrChunks.join(''), '');

  assert.equal(
    await sdk.runCli(['--binary-path'], {
      localParserPath: parserDist,
      stdout,
      stderr
    }),
    1
  );
  assert.match(stderrChunks.join(''), /requires a value/);

  const cliCode = await sdk.runCli(
    ['--binary-path', fixtureBinary, 'dns', 'record', 'lookup', 'example.com', '--type', 'MX'],
    {
      env: {
        RB_FAKE_LOG_PATH: logPath
      },
      localParserPath: parserDist,
      stdio: 'ignore'
    }
  );
  assert.equal(cliCode, 0);

  const cliLog = readLogLines(logPath);
  assert.deepEqual(cliLog[0], ['dns', 'record', 'lookup', 'example.com', '--type', 'MX']);

  assert.equal(
    await sdk.runCli(['--binary-path', fixtureBinary], {
      cwd: tmpDir,
      localParserPath: parserDist,
      stdio: 'ignore'
    }),
    0
  );

  assert.equal(
    await sdk.runCli(['--binary-path', process.execPath, '-e', 'process.exit(0)'], {
      localParserPath: parserDist
    }),
    0
  );

  const child = spawnBinary(
    process.execPath,
    [
      sdkScript,
      '--binary-path',
      fixtureBinary,
      'network',
      'ports',
      'scan',
      '10.0.0.9',
      '--preset',
      'common'
    ],
    {
      env: Object.assign({}, process.env, {
        RB_FAKE_LOG_PATH: logPath,
        REDBLUE_CLI_ARGS_PARSER_PATH: parserDist
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
  assert.deepEqual(mainLog[1], [
    'network',
    'ports',
    'scan',
    '10.0.0.9',
    '--preset',
    'common'
  ]);

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

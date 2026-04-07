'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const SDK_DIR = path.join(ROOT_DIR, 'sdk');
const OUTPUT_DTS = path.join(SDK_DIR, 'generated-routes.d.ts');
const OUTPUT_JSON = path.join(SDK_DIR, 'generated-routes.json');
const DEFAULT_BINARY = path.join(
  ROOT_DIR,
  'target',
  'debug',
  process.platform === 'win32' ? 'redblue.exe' : 'redblue'
);

function parseArgs(argv) {
  const options = {
    check: false,
    manifestPath: null,
    binaryPath: process.env.REDBLUE_BINARY_PATH || DEFAULT_BINARY
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === '--check') {
      options.check = true;
      continue;
    }

    if (token === '--manifest' && index + 1 < argv.length) {
      options.manifestPath = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }

    if (token === '--binary' && index + 1 < argv.length) {
      options.binaryPath = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  return options;
}

function loadManifestFromBinary(binaryPath) {
  if (!fs.existsSync(binaryPath)) {
    throw new Error(
      `redblue binary not found at ${binaryPath}. Use --manifest <file> or --binary <path>.`
    );
  }

  const result = spawnSync(binaryPath, ['sdk', 'bridge', 'manifest'], {
    cwd: ROOT_DIR,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    const stderr = String(result.stderr || '').trim();
    throw new Error(`Failed to read manifest from ${binaryPath}: ${stderr || 'unknown error'}`);
  }

  const stdout = String(result.stdout || '').trim();
  if (!stdout) {
    throw new Error(`Manifest command returned empty output from ${binaryPath}`);
  }

  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(`Failed to parse manifest JSON from ${binaryPath}: ${error.message}`);
  }
}

function loadManifest(options) {
  if (options.manifestPath) {
    if (!fs.existsSync(options.manifestPath)) {
      throw new Error(`Manifest file not found: ${options.manifestPath}`);
    }

    return JSON.parse(fs.readFileSync(options.manifestPath, 'utf8'));
  }

  return loadManifestFromBinary(options.binaryPath);
}

function collectCanonicalRoutes(manifest) {
  const commands = Array.isArray(manifest.commands) ? manifest.commands : [];
  const routes = [];
  const seen = new Set();

  for (const command of commands) {
    const domain = String(command.domain || '').trim();
    const resource = String(command.resource || '').trim();
    if (!domain || !resource) {
      continue;
    }

    for (const route of Array.isArray(command.routes) ? command.routes : []) {
      const verb = String(route.verb || '').trim();
      if (!verb) {
        continue;
      }

      const canonicalPath = String(route.canonical_path || `${domain}/${resource}/${verb}`).trim();
      if (!canonicalPath || seen.has(canonicalPath)) {
        continue;
      }

      seen.add(canonicalPath);
      routes.push({
        domain,
        resource,
        verb,
        canonical_path: canonicalPath
      });
    }
  }

  routes.sort((left, right) => {
    if (left.domain !== right.domain) {
      return left.domain.localeCompare(right.domain);
    }
    if (left.resource !== right.resource) {
      return left.resource.localeCompare(right.resource);
    }
    return left.verb.localeCompare(right.verb);
  });

  return routes;
}

function buildRouteTree(routes) {
  const tree = {};

  for (const entry of routes) {
    if (!Object.prototype.hasOwnProperty.call(tree, entry.domain)) {
      tree[entry.domain] = {};
    }
    if (!Object.prototype.hasOwnProperty.call(tree[entry.domain], entry.resource)) {
      tree[entry.domain][entry.resource] = [];
    }
    tree[entry.domain][entry.resource].push(entry.verb);
  }

  for (const domain of Object.keys(tree)) {
    for (const resource of Object.keys(tree[domain])) {
      tree[domain][resource] = Array.from(new Set(tree[domain][resource])).sort((a, b) =>
        a.localeCompare(b)
      );
    }
  }

  return tree;
}

function emitLiteralUnion(name, values) {
  if (!Array.isArray(values) || values.length === 0) {
    return `export type ${name} = never;\n`;
  }

  const lines = [`export type ${name} =`];
  for (const value of values) {
    lines.push(`  | ${JSON.stringify(value)}`);
  }
  lines.push(';\n');
  return `${lines.join('\n')}\n`;
}

function emitTupleUnion(name, routes) {
  if (!Array.isArray(routes) || routes.length === 0) {
    return `export type ${name} = never;\n`;
  }

  const lines = [`export type ${name} =`];
  for (const route of routes) {
    lines.push(
      `  | [${JSON.stringify(route.domain)}, ${JSON.stringify(route.resource)}, ${JSON.stringify(route.verb)}]`
    );
  }
  lines.push(';\n');
  return `${lines.join('\n')}\n`;
}

function emitRouteSurfaceInterface(tree) {
  const lines = ['export interface GeneratedRouteSurface<TInvocation = unknown> {'];

  const domains = Object.keys(tree).sort((left, right) => left.localeCompare(right));
  for (const domain of domains) {
    lines.push(`  ${JSON.stringify(domain)}: {`);
    const resources = Object.keys(tree[domain]).sort((left, right) => left.localeCompare(right));
    for (const resource of resources) {
      lines.push(`    ${JSON.stringify(resource)}: {`);
      for (const verb of tree[domain][resource]) {
        lines.push(`      ${JSON.stringify(verb)}: TInvocation;`);
      }
      lines.push('    };');
    }
    lines.push('  };');
  }

  lines.push('}');
  lines.push('');
  return lines.join('\n');
}

function renderDts(manifest, routes, tree) {
  const header = [
    '// @generated by scripts/generate-sdk-surface.js',
    '// Manifest-driven route typing contract. Do not edit manually.',
    ''
  ];

  const canonicalPaths = routes.map((route) => route.canonical_path);
  return (
    `${header.join('\n')}\n` +
    emitLiteralUnion('GeneratedCanonicalRoutePath', canonicalPaths) +
    emitTupleUnion('GeneratedRouteTuple', routes) +
    emitRouteSurfaceInterface(tree) +
    `export interface GeneratedRouteContract {\n` +
    `  schema_version: number;\n` +
    `  manifest_version: string;\n` +
    `  route_count: number;\n` +
    `  routes: GeneratedCanonicalRoutePath[];\n` +
    `}\n`
  );
}

function buildJsonContract(manifest, routes, tree) {
  return {
    schema_version: 1,
    manifest_version: String(manifest.version || ''),
    route_count: routes.length,
    routes: routes.map((route) => route.canonical_path),
    route_tree: tree
  };
}

function ensureFileMatches(filePath, expectedContent) {
  if (!fs.existsSync(filePath)) {
    return false;
  }
  const current = fs.readFileSync(filePath, 'utf8');
  return current === expectedContent;
}

function writeFileIfChanged(filePath, content) {
  if (ensureFileMatches(filePath, content)) {
    return false;
  }
  fs.writeFileSync(filePath, content, 'utf8');
  return true;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = loadManifest(options);
  const routes = collectCanonicalRoutes(manifest);
  const routeTree = buildRouteTree(routes);
  const dtsContent = renderDts(manifest, routes, routeTree);
  const jsonContent = `${JSON.stringify(buildJsonContract(manifest, routes, routeTree), null, 2)}\n`;

  if (options.check) {
    const dtsMatches = ensureFileMatches(OUTPUT_DTS, dtsContent);
    const jsonMatches = ensureFileMatches(OUTPUT_JSON, jsonContent);
    if (!dtsMatches || !jsonMatches) {
      const stale = [];
      if (!dtsMatches) {
        stale.push(path.relative(ROOT_DIR, OUTPUT_DTS));
      }
      if (!jsonMatches) {
        stale.push(path.relative(ROOT_DIR, OUTPUT_JSON));
      }
      throw new Error(
        `SDK surface artifacts are stale: ${stale.join(', ')}. Run: node scripts/generate-sdk-surface.js`
      );
    }

    console.log('SDK surface artifacts are up to date.');
    return;
  }

  const changedFiles = [];
  if (writeFileIfChanged(OUTPUT_DTS, dtsContent)) {
    changedFiles.push(path.relative(ROOT_DIR, OUTPUT_DTS));
  }
  if (writeFileIfChanged(OUTPUT_JSON, jsonContent)) {
    changedFiles.push(path.relative(ROOT_DIR, OUTPUT_JSON));
  }

  if (changedFiles.length === 0) {
    console.log('SDK surface artifacts already up to date.');
    return;
  }

  console.log(`Updated SDK surface artifacts:\n  - ${changedFiles.join('\n  - ')}`);
}

try {
  main();
} catch (error) {
  console.error(`generate-sdk-surface: ${error.message}`);
  process.exit(1);
}

#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const versionPath = path.join(rootDir, 'VERSION');
const cargoTomlPath = path.join(rootDir, 'Cargo.toml');
const packageJsonPath = path.join(rootDir, 'package.json');

const args = process.argv.slice(2);
const setIndex = args.indexOf('--set');

function readVersion() {
  return fs.readFileSync(versionPath, 'utf8').trim();
}

function validateVersion(version) {
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`invalid version: ${version}`);
  }
}

function writeVersion(version) {
  fs.writeFileSync(versionPath, `${version}\n`, 'utf8');
}

function syncCargoToml(version) {
  const cargoToml = fs.readFileSync(cargoTomlPath, 'utf8');
  const currentMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"$/m);
  if (!currentMatch) {
    throw new Error('failed to find Cargo.toml version');
  }
  if (currentMatch[1] === version) {
    return;
  }

  const next = cargoToml.replace(
    /^version\s*=\s*"[^"]+"$/m,
    `version = "${version}"`
  );

  fs.writeFileSync(cargoTomlPath, next, 'utf8');
}

function syncPackageJson(version) {
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  if (packageJson.version === version) {
    return;
  }
  packageJson.version = version;
  fs.writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`, 'utf8');
}

try {
  let version = readVersion();

  if (setIndex !== -1) {
    version = args[setIndex + 1];
    if (!version) {
      throw new Error('missing value after --set');
    }
    validateVersion(version);
    writeVersion(version);
  } else {
    validateVersion(version);
  }

  // If the CI release workflow already set a different version in package.json
  // (prerelease like 0.2.2-next.48 or a newer stable like 0.2.6), don't
  // overwrite it with the VERSION file's base version. This prevents:
  // - Republishing an already-published stable version
  // - Downgrading a version that the release workflow intentionally set
  const currentPkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const pkgVersion = currentPkg.version || '';
  const shouldKeepPkg = pkgVersion !== version && pkgVersion.length > 0 && (
    pkgVersion.includes('-') ||  // prerelease: 0.2.2-next.48
    pkgVersion > version         // newer stable: 0.2.6 > 0.2.2
  );

  if (shouldKeepPkg) {
    process.stdout.write(`Synced version ${version} (kept package.json at ${pkgVersion})\n`);
    syncCargoToml(version);
  } else {
    syncCargoToml(version);
    syncPackageJson(version);
    process.stdout.write(`Synced version ${version}\n`);
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
